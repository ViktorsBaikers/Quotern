mod support;

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, OptionalExtension};
use tempfile::tempdir;

use quotern_core::ingest::sqlite_ro::{open_canonical, reset_vfs_metrics, vfs_metrics};
use support::vfs_probe::VfsProbe;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use support::vfs_probe::kernel;
use support::{TestResult, WriterChild, start_existing_writer, start_writer};

type MirrorObservation = (String, Option<u64>, bool, u64);

#[test]
fn sqlite_version_is_recorded() -> TestResult {
    let connection = Connection::open_in_memory()?;
    let (version, source_id) =
        quotern_core::ingest::sqlite_ro::linked_sqlite_identity(&connection)?;
    println!("sqlite_version={version} sqlite_source_id={source_id}");
    assert_eq!(version.split('.').count(), 3);
    assert!(source_id.len() >= 64);
    Ok(())
}

#[test]
fn spike_m1_is_rejected_for_write_capable_wal_open() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let database = directory.path().join("opencode.db");
    let writer = Connection::open(&database)?;
    let mode: String = writer.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
    assert_eq!(mode, "wal");
    writer.execute_batch(
        "CREATE TABLE records(id TEXT PRIMARY KEY); INSERT INTO records VALUES ('wal-only');",
    )?;
    writer.pragma_update(None, "wal_autocheckpoint", 0)?;
    assert!(Path::new(&format!("{}-wal", database.display())).exists());
    assert!(Path::new(&format!("{}-shm", database.display())).exists());

    let before = source_image(&database)?;
    let probe = VfsProbe::new("quotern-m1-probe")?;
    let uri = format!(
        "file:{}?mode=ro&readonly_shm=1",
        database.canonicalize()?.display()
    );
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_URI
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let reader = Connection::open_with_flags_and_vfs(uri, flags, probe.name().as_c_str())?;
    let rows: i64 = reader.query_row("SELECT COUNT(*) FROM records", [], |row| row.get(0))?;
    assert_eq!(rows, 1);
    drop(reader);

    let counts = probe.counts();
    assert_eq!(
        counts.write_capable_opens, 1,
        "observed VFS opens: {counts:?}"
    );
    let after = source_image(&database)?;
    assert_eq!(before.len(), after.len());
    let changed = before
        .iter()
        .zip(&after)
        .filter(|((_, before), (_, after))| before != after)
        .map(|((path, _), _)| path.clone())
        .collect::<Vec<_>>();
    println!(
        "M1 rejected: write_capable_opens={} changed_files={changed:?}",
        counts.write_capable_opens
    );
    Ok(())
}

#[test]
fn spike_m2_live_writer_reads_wal_without_source_effects() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let database = directory.path().join("opencode.db");
    let mut writer = start_writer(&database)?;
    assert!(Path::new(&format!("{}-wal", database.display())).exists());
    assert!(Path::new(&format!("{}-shm", database.display())).exists());
    let before = source_image(&database)?;
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let (keys, probe) = (
        kernel::source_keys(&database)?,
        kernel::SyscallProbe::start()?,
    );
    reset_vfs_metrics()?;

    let reader = open_canonical(&database.canonicalize()?)?;
    let rows: i64 = reader.query_row("SELECT COUNT(*) FROM records", [], |row| row.get(0))?;
    assert_eq!(rows, 1);
    let error = reader.execute("INSERT INTO records VALUES ('forbidden')", []);
    assert!(
        matches!(error, Err(rusqlite::Error::SqliteFailure(code, _)) if code.code == rusqlite::ffi::ErrorCode::ReadOnly)
    );
    // Independent kernel view while the reader and its read transaction are alive: the descriptors
    // SQLite and the VFS hold (the direct WAL descriptor included) and the live SHM mappings.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        reader.execute_batch("BEGIN")?;
        let again: i64 = reader.query_row("SELECT COUNT(*) FROM records", [], |row| row.get(0))?;
        assert_eq!(again, 1);
        let samples = kernel::live_source_fds(&keys)?;
        // Borrowed descriptors are never closed by the sweep: a second sweep sees the same set.
        let descriptors = |samples: &[kernel::FdSample]| {
            samples.iter().map(|sample| sample.fd).collect::<Vec<_>>()
        };
        assert_eq!(
            descriptors(&samples),
            descriptors(&kernel::live_source_fds(&keys)?)
        );
        let events = probe.events();
        assert_m2_kernel_readonly(&keys, Some(&samples), &events)?;
        for map in events.maps_of(&keys, kernel::SHM) {
            // Re-queried while the reader is alive: still not writable.
            let protection = kernel::map_protection(map.address as *mut _, map.length)?;
            assert_eq!(protection & kernel::PROT_WRITE, 0, "{map:?}");
        }
        reader.execute_batch("COMMIT")?;
    }
    drop(reader);

    let counts = vfs_metrics()?;
    assert!(
        counts.stripped_write_capable_requests > 0,
        "SQLite WAL open requests observed: {counts:?}"
    );
    assert_eq!(
        counts.write_capable_opens, 0,
        "delegated VFS opens: {counts:?}"
    );
    assert_eq!(counts.writes, 0, "write callbacks: {counts:?}");
    assert_eq!(counts.truncates, 0, "truncate callbacks: {counts:?}");
    assert_eq!(counts.syncs, 0, "sync callbacks: {counts:?}");
    assert_eq!(counts.deletes, 0, "delete callbacks: {counts:?}");
    assert!(
        counts.shared_memory_maps > 0,
        "shared-memory mappings: {counts:?}"
    );
    assert_source_unchanged(&database, &before)?;
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    assert_m2_kernel_readonly(&keys, None, &probe.finish()?)?;
    writer.stop()?;
    Ok(())
}

#[test]
fn sqlite_writer_child_entrypoint() -> TestResult {
    support::writer_child_main()
}

fn source_image(database: &Path) -> std::io::Result<Vec<(PathBuf, Option<Vec<u8>>)>> {
    [
        database.to_path_buf(),
        PathBuf::from(format!("{}-wal", database.display())),
        PathBuf::from(format!("{}-shm", database.display())),
        PathBuf::from(format!("{}-journal", database.display())),
    ]
    .into_iter()
    .map(|path| match std::fs::read(&path) {
        Ok(bytes) => Ok((path, Some(bytes))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok((path, None)),
        Err(error) => Err(error),
    })
    .collect()
}
#[test]
fn opencode_payload_above_256_kib_is_rejected() {
    let empty_payload = r#"{"role":"assistant","tokens":{"input":1,"total":1},"content":""}"#;
    let payload_of_length = |length: usize| {
        let mut payload = empty_payload.to_owned();
        payload.insert_str(payload.len() - 2, &"x".repeat(length - payload.len()));
        payload
    };
    let decode = |payload: &str| {
        quotern_core::adapters::opencode::decode_record(
            "session",
            "message",
            Some(1),
            None,
            payload.as_bytes(),
            Path::new("/source/opencode.db"),
            0,
        )
    };
    let exact = payload_of_length(256 * 1024);
    assert_eq!(exact.len(), 256 * 1024);
    assert!(decode(&exact).is_ok());

    let over_limit = payload_of_length(256 * 1024 + 1);
    assert_eq!(over_limit.len(), 256 * 1024 + 1);
    assert_eq!(
        decode(&over_limit),
        Err(quotern_core::adapters::opencode::DecodeError::RecordTooLarge)
    );
}

#[test]
fn opencode_reported_counts_stop_at_one_trillion() {
    let above_limit =
        br#"{"role":"assistant","tokens":{"input":1000000000001,"total":1000000000001}}"#;
    let error = quotern_core::adapters::opencode::decode_record(
        "session",
        "above-limit",
        Some(1),
        None,
        above_limit,
        Path::new("/source/opencode.db"),
        0,
    );
    assert_eq!(
        error,
        Err(quotern_core::adapters::opencode::DecodeError::InvalidRecord)
    );

    let at_limit =
        br#"{"role":"assistant","tokens":{"input":1000000000000,"total":1000000000000}}"#;
    let record = quotern_core::adapters::opencode::decode_record(
        "session",
        "at-limit",
        Some(1),
        None,
        at_limit,
        Path::new("/source/opencode.db"),
        0,
    )
    .expect("the maximum supported reported count is valid");
    assert_eq!(record.total, Some(1_000_000_000_000));
}

#[test]
fn opencode_record_identity_bounds_and_controls_are_enforced() {
    let payload = br#"{"role":"assistant","tokens":{"input":1,"total":1}}"#;
    let decode = |session_id: &str, message_id: &str| {
        quotern_core::adapters::opencode::decode_record(
            session_id,
            message_id,
            Some(1),
            None,
            payload,
            Path::new("/source/opencode.db"),
            0,
        )
    };

    let session_id = "s".repeat(256);
    let message_id = "m".repeat(256);
    assert!(decode(&session_id, &message_id).is_ok());

    assert_eq!(
        decode("s".repeat(257).as_str(), "message"),
        Err(quotern_core::adapters::opencode::DecodeError::InvalidRecord)
    );
    assert_eq!(
        decode("session\nforged", "message"),
        Err(quotern_core::adapters::opencode::DecodeError::InvalidRecord)
    );
}
static VFS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn vfs_test_guard() -> std::sync::MutexGuard<'static, ()> {
    VFS_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn source_roots(base: &Path) -> TestResult<(PathBuf, PathBuf, PathBuf)> {
    let source = base.join("source");
    let data = base.join("data");
    let home = base.join("home");
    std::fs::create_dir(&source)?;
    std::fs::create_dir(&home)?;
    Ok((source, data, home))
}

fn open_engine(
    source: &Path,
    data: &Path,
    home: &Path,
) -> TestResult<quotern_core::ingest::OpenCodeEngine<quotern_core::ingest::fs::RealSourceFs>> {
    match quotern_core::ingest::OpenCodeEngine::open(
        quotern_core::ingest::fs::RealSourceFs,
        source,
        data,
        home,
        quotern_core::domain::SourceAuthorization {
            selected: true,
            consent: quotern_core::domain::ConsentState::Enabled,
        },
        quotern_core::domain::SourceKind::Custom,
    ) {
        Ok(engine) => Ok(engine),
        Err(report) => Err(format!("OpenCode engine failed: {report:?}").into()),
    }
}

fn expected_peer_case(name: &str) -> TestResult<serde_json::Value> {
    let cases: Vec<serde_json::Value> = serde_json::from_slice(include_bytes!(
        "../../../Fixtures/harness/opencode/peer/expected.json"
    ))?;
    cases
        .into_iter()
        .find(|case| case["name"].as_str() == Some(name))
        .ok_or_else(|| format!("missing peer oracle case {name}").into())
}

fn assert_peer_observation(
    observation: &quotern_core::domain::SourceReportedObservation,
    expected: &serde_json::Value,
) {
    assert_eq!(
        observation.record_id,
        expected["record_id"].as_str().unwrap()
    );
    for (name, component) in [
        ("input", &observation.input),
        ("output", &observation.output),
        ("reasoning", &observation.reasoning),
        ("cache_read", &observation.cache_read),
        ("cache_write", &observation.cache_write),
        ("total", &observation.total),
    ] {
        if let Some(value) = expected.get(name) {
            assert_eq!(component.value, value.as_u64(), "{name}");
        }
    }
    if let Some(value) = expected.get("total_provenance") {
        let provenance = match value.as_str() {
            Some("reported") => Some(quotern_core::domain::Provenance::Reported),
            Some("derived") => Some(quotern_core::domain::Provenance::Derived),
            _ => None,
        };
        assert_eq!(observation.total.provenance, provenance);
    }
    if let Some(value) = expected.get("source_convention") {
        assert_eq!(observation.source_convention.as_deref(), value.as_str());
    }
    if let Some(value) = expected.get("total_mismatch") {
        assert_eq!(observation.total_mismatch, value.as_bool().unwrap());
    }
    assert_eq!(
        observation.origin_uncertainty,
        quotern_core::domain::OriginUncertainty::UnverifiedOrigin
    );
    assert_eq!(observation.revision, 1);
    assert!(!observation.pending_partial);
}

fn assert_vfs_read_only() -> TestResult {
    let metrics = vfs_metrics()?;
    assert!(metrics.stripped_write_capable_requests > 0, "{metrics:?}");
    assert_eq!(metrics.write_capable_opens, 0, "{metrics:?}");
    assert_eq!(metrics.writes, 0, "{metrics:?}");
    assert_eq!(metrics.truncates, 0, "{metrics:?}");
    assert_eq!(metrics.syncs, 0, "{metrics:?}");
    assert_eq!(metrics.deletes, 0, "{metrics:?}");
    assert!(metrics.shared_memory_maps > 0, "{metrics:?}");
    // Kernel-reported protection and access mode, independent of the flags this VFS chose.
    assert!(metrics.readonly_shared_memory_maps > 0, "{metrics:?}");
    assert_eq!(
        metrics.writable_shared_memory_maps_rejected, 0,
        "{metrics:?}"
    );
    assert_eq!(
        metrics.unverified_shared_memory_maps_rejected, 0,
        "{metrics:?}"
    );
    assert_eq!(
        metrics.effective_write_capable_descriptors, 0,
        "{metrics:?}"
    );
    assert_eq!(metrics.nonregular_descriptors_rejected, 0, "{metrics:?}");
    assert_eq!(metrics.metadata_effects_blocked, 0, "{metrics:?}");
    assert!(metrics.descriptors_verified > 0, "{metrics:?}");
    Ok(())
}

#[test]
fn spike_s1_live_child_reads_wal_only_reported_usage() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let database = source.join("opencode.db");
    let mut writer = start_writer(&database)?;
    assert!(Path::new(&format!("{}-wal", database.display())).exists());
    assert!(Path::new(&format!("{}-shm", database.display())).exists());
    let before = source_image(&database)?;
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let (keys, probe) = (
        kernel::source_keys(&database)?,
        kernel::SyscallProbe::start()?,
    );
    reset_vfs_metrics()?;

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let sweeps = {
        let sweeps = Sweeps::default();
        sweep_on_shm_open(
            keys,
            sidecar(&database.canonicalize()?, "-shm"),
            Sweeps::clone(&sweeps),
            kernel::live_source_fds,
        );
        sweeps
    };
    let mut engine = open_engine(&source, &data, &home)?;
    let report = engine.pass(
        quotern_core::domain::SourceAuthorization {
            selected: true,
            consent: quotern_core::domain::ConsentState::Enabled,
        },
        1700000001000,
    );
    assert_eq!(
        report.outcome,
        quotern_core::domain::PassOutcome::Consistent
    );
    assert_eq!(report.records_committed, 1);
    let observations = engine.observations()?;
    assert_eq!(observations.len(), 1);
    let expected = expected_peer_case("named_convention_derives_42")?;
    assert_peer_observation(&observations[0], &expected);
    assert_eq!(observations[0].total.value, Some(42));
    assert_source_unchanged(&database, &before)?;
    assert!(!data.join("opencode.db").exists());
    assert_vfs_read_only()?;
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        // The acquisition handles are closed inside the pass; the parent-chain events prove the
        // database and SHM descriptors and every mapping the engine's reader caused, and the
        // sweeps taken while the engine itself held its direct WAL descriptor prove that one.
        quotern_core::ingest::sqlite_ro::set_open_hook(None);
        let sweeps = sweeps.borrow();
        // Every sweep taken is a result: a failed one is as much a failure of the access proof as
        // an empty one, and is surfaced here, outside the engine's C callback.
        sweeps.complete()?;
        for samples in &sweeps.samples {
            assert!(
                samples.iter().any(|sample| sample.kind == kernel::WAL),
                "the engine's direct WAL descriptor was not live: {samples:?}"
            );
            assert!(
                samples.iter().any(|sample| sample.kind == kernel::DB),
                "{samples:?}"
            );
            kernel::readonly_fd_oracle(samples)?;
        }
        let events = probe.finish()?;
        assert_m2_kernel_readonly(&keys, None, &events)?;
    }
    writer.stop()?;
    Ok(())
}

/// What the live-descriptor sweeps taken while the engine held its direct WAL descriptor saw. A
/// failed sweep is kept, never dropped: it would otherwise leave only the successful ones to speak
/// for a proof it did not complete. The sweep runs inside a C callback, so it records instead of
/// unwinding or returning an error across the boundary.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Default)]
struct SweepLog {
    samples: Vec<Vec<kernel::FdSample>>,
    failures: Vec<String>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl SweepLog {
    /// At least one sweep ran and none of them failed.
    fn complete(&self) -> TestResult {
        if !self.failures.is_empty() {
            return Err(format!(
                "{} live descriptor sweep(s) failed after {} succeeded: {:?}",
                self.failures.len(),
                self.samples.len(),
                self.failures
            )
            .into());
        }
        if self.samples.is_empty() {
            return Err("the engine never opened the sidecar".into());
        }
        Ok(())
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
type Sweeps = std::rc::Rc<std::cell::RefCell<SweepLog>>;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
type Sweep = fn(&kernel::SourceKeys) -> Result<Vec<kernel::FdSample>, String>;

/// Samples every live source descriptor each time the engine's read opens the shared-memory
/// sidecar: SQLite opens the write-ahead log (through the VFS's own descriptor, which no parent
/// `open` ever sees) before it maps the shared memory, so the engine holds it at that instant.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn sweep_on_shm_open(keys: kernel::SourceKeys, shm: PathBuf, sweeps: Sweeps, sweep: Sweep) {
    let next = Sweeps::clone(&sweeps);
    quotern_core::ingest::sqlite_ro::set_open_hook(Some(Box::new(move |path| {
        if path == shm {
            match sweep(&keys) {
                Ok(samples) => next.borrow_mut().samples.push(samples),
                Err(failure) => next.borrow_mut().failures.push(failure),
            }
        }
        sweep_on_shm_open(keys, shm.clone(), Sweeps::clone(&next), sweep);
    })));
}

#[test]
fn peer_reported_records() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let database = source.join("opencode.db");
    let writer = Connection::open(&database)?;
    writer.execute_batch(include_str!(
        "../../../Fixtures/harness/opencode/wal/schema.sql"
    ))?;
    let cases: Vec<serde_json::Value> = serde_json::from_slice(include_bytes!(
        "../../../Fixtures/harness/opencode/peer/cases.json"
    ))?;
    let expected: Vec<serde_json::Value> = serde_json::from_slice(include_bytes!(
        "../../../Fixtures/harness/opencode/peer/expected.json"
    ))?;
    for case in &cases {
        let format = case["format"].as_str().expect("fixture format");
        let session_id = case["session_id"].as_str().expect("fixture session id");
        let message_id = case["message_id"].as_str().expect("fixture message id");
        let time_created = case["time_created"].as_i64();
        let payload = serde_json::to_vec(&case["data"])?;
        match format {
            "legacy" => {
                writer.execute(
                    "INSERT INTO message(id, session_id, time_created, data) VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params![message_id, session_id, time_created, payload],
                )?;
            }
            "v2" => {
                let record_type = case["record_type"].as_str().expect("fixture v2 type");
                writer.execute(
                    "INSERT OR IGNORE INTO session_v2(id) VALUES (?1)",
                    [session_id],
                )?;
                writer.execute(
                    "INSERT INTO session_message(id, session_id, type, seq, time_created, data) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![
                        message_id,
                        session_id,
                        record_type,
                        1_i64,
                        time_created,
                        payload
                    ],
                )?;
            }
            "json" => {
                let mut message = case["data"].clone();
                message["time"] = serde_json::json!({ "created": case["time_created"] });
                let path = source
                    .join("storage")
                    .join("message")
                    .join(session_id)
                    .join(format!("{message_id}.json"));
                std::fs::create_dir_all(path.parent().expect("fixture message parent"))?;
                std::fs::write(path, serde_json::to_vec(&message)?)?;
            }
            other => return Err(format!("unknown fixture format {other}").into()),
        }
    }
    drop(writer);
    let mut child_writer = start_existing_writer(&database)?;
    let before = source_image(&database)?;
    reset_vfs_metrics()?;

    let mut engine = open_engine(&source, &data, &home)?;
    let report = engine.pass(
        quotern_core::domain::SourceAuthorization {
            selected: true,
            consent: quotern_core::domain::ConsentState::Enabled,
        },
        1700000010000,
    );
    assert_eq!(report.outcome, quotern_core::domain::PassOutcome::Partial);
    assert_eq!(
        report.failure,
        Some(quotern_core::domain::FailureCode::InvalidRecord)
    );
    assert_eq!(report.counters.rejected_records, 4);
    assert_eq!(report.records_committed, 7);
    let observations = engine.observations()?;
    assert_eq!(observations.len(), 7);
    for expected_case in expected.iter().filter(|case| case["accepted"] == true) {
        let id = expected_case["record_id"]
            .as_str()
            .expect("accepted oracle id");
        let observation = observations
            .iter()
            .find(|row| row.record_id == id)
            .unwrap_or_else(|| {
                panic!(
                    "missing {id}; actual IDs: {:?}",
                    observations
                        .iter()
                        .map(|row| row.record_id.as_str())
                        .collect::<Vec<_>>()
                )
            });
        assert_peer_observation(observation, expected_case);
    }
    assert_source_unchanged(&database, &before)?;
    assert_vfs_read_only()?;
    child_writer.stop()?;
    Ok(())
}

fn assert_source_unchanged(database: &Path, before: &[(PathBuf, Option<Vec<u8>>)]) -> TestResult {
    let after = source_image(database)?;
    assert_eq!(before.len(), after.len());
    let changed = before
        .iter()
        .zip(&after)
        .filter(|((before_path, before_bytes), (after_path, after_bytes))| {
            before_path != after_path || before_bytes != after_bytes
        })
        .map(|((before_path, _), _)| before_path.display().to_string())
        .collect::<Vec<_>>();
    assert!(
        changed.is_empty(),
        "source files changed during read: {changed:?}"
    );
    Ok(())
}

fn consented() -> quotern_core::domain::SourceAuthorization {
    quotern_core::domain::SourceAuthorization {
        selected: true,
        consent: quotern_core::domain::ConsentState::Enabled,
    }
}
fn open_recording_engine(
    fs: quotern_core::ingest::fs::RecordingFs,
    source: &Path,
    data: &Path,
    home: &Path,
) -> Result<
    quotern_core::ingest::OpenCodeEngine<quotern_core::ingest::fs::RecordingFs>,
    quotern_core::domain::PassReport,
> {
    quotern_core::ingest::OpenCodeEngine::open(
        fs,
        source,
        data,
        home,
        consented(),
        quotern_core::domain::SourceKind::Custom,
    )
}

fn assert_vfs_no_mutations() -> TestResult {
    let metrics = vfs_metrics()?;
    assert_eq!(metrics.write_capable_opens, 0, "{metrics:?}");
    assert_eq!(metrics.writes, 0, "{metrics:?}");
    assert_eq!(metrics.truncates, 0, "{metrics:?}");
    assert_eq!(metrics.syncs, 0, "{metrics:?}");
    assert_eq!(metrics.deletes, 0, "{metrics:?}");
    Ok(())
}

#[test]
fn spike_s2_clean_close_without_sidecars_is_idle() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let database = source.join("opencode.db");
    let mut writer = start_writer(&database)?;
    writer.stop()?;
    let before = source_image(&database)?;
    assert!(before[1].1.is_none());
    assert!(before[2].1.is_none());

    let fs = quotern_core::ingest::fs::RecordingFs::new();
    let observed = fs.clone();
    let mut engine = open_recording_engine(fs, &source, &data, &home)
        .map_err(|report| format!("OpenCode engine failed: {report:?}"))?;
    let report = engine.pass(consented(), 2);
    assert_eq!(
        report.outcome,
        quotern_core::domain::PassOutcome::Unavailable
    );
    assert_eq!(
        report.failure,
        Some(quotern_core::domain::FailureCode::SourceIdle)
    );
    assert_eq!(report.counters.header_reads, 1);
    assert_eq!(observed.metrics().sqlite_opens, 0);
    assert_source_unchanged(&database, &before)?;
    Ok(())
}

#[test]
fn spike_s3_crashed_writer_is_oracle_or_unavailable_without_effects() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let database = source.join("opencode.db");
    let mut writer = start_writer(&database)?;
    writer.crash()?;
    let before = source_image(&database)?;
    assert!(before[1].1.is_some());
    assert!(before[2].1.is_some());
    reset_vfs_metrics()?;

    let mut engine = open_engine(&source, &data, &home)?;
    let report = engine.pass(consented(), 3);
    match report.outcome {
        quotern_core::domain::PassOutcome::Consistent => {
            let observations = engine.observations()?;
            assert_eq!(observations.len(), 1);
            assert_peer_observation(
                &observations[0],
                &expected_peer_case("named_convention_derives_42")?,
            );
        }
        quotern_core::domain::PassOutcome::Unavailable => {
            assert!(report.failure.is_some());
            assert!(engine.observations()?.is_empty());
            assert_eq!(report.records_committed, 0);
        }
        outcome => panic!("crashed writer produced an unsafe {outcome:?} outcome: {report:?}"),
    }
    assert_source_unchanged(&database, &before)?;
    assert_vfs_no_mutations()?;
    Ok(())
}
#[test]
fn spike_s4_read_transaction_keeps_writer_commit_out_of_snapshot() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, _data, _home) = source_roots(directory.path())?;
    let database = source.join("opencode.db");
    let mut writer = start_writer(&database)?;
    reset_vfs_metrics()?;

    let reader = open_canonical(&database.canonicalize()?)?;
    reader.execute_batch("BEGIN DEFERRED;")?;
    let initial: i64 =
        reader.query_row("SELECT COUNT(*) FROM session_message", [], |row| row.get(0))?;
    assert_eq!(initial, 1);
    writer.command("append", "COMMITTED")?;
    let during: i64 =
        reader.query_row("SELECT COUNT(*) FROM session_message", [], |row| row.get(0))?;
    assert_eq!(during, initial);
    let after_external_commit = source_image(&database)?;

    reader.execute_batch("COMMIT;")?;
    let refreshed: i64 =
        reader.query_row("SELECT COUNT(*) FROM session_message", [], |row| row.get(0))?;
    assert_eq!(refreshed, 2);
    drop(reader);
    assert_source_unchanged(&database, &after_external_commit)?;
    assert_vfs_read_only()?;
    writer.stop()?;
    Ok(())
}

#[test]
fn spike_s5_exclusive_writer_lock_is_bounded_busy() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let database = source.join("opencode.db");
    let mut writer = start_writer(&database)?;
    let mut engine = open_engine(&source, &data, &home)?;
    writer.command("exclusive", "LOCKED")?;
    reset_vfs_metrics()?;

    let (sender, receiver) = std::sync::mpsc::channel();
    let reader_thread = std::thread::spawn(move || {
        let report = engine.pass(consented(), 4);
        sender
            .send(report)
            .expect("test receiver remains connected");
    });
    let report = match receiver.recv_timeout(std::time::Duration::from_secs(1)) {
        Ok(report) => report,
        Err(error) => {
            writer.command("release", "RELEASED")?;
            reader_thread
                .join()
                .map_err(|_| std::io::Error::other("source reader thread panicked"))?;
            return Err(
                format!("SQLite busy result exceeded the one-second deadline: {error}").into(),
            );
        }
    };
    reader_thread
        .join()
        .map_err(|_| std::io::Error::other("source reader thread panicked"))?;
    assert_eq!(
        report.outcome,
        quotern_core::domain::PassOutcome::Unavailable
    );
    assert_eq!(
        report.failure,
        Some(quotern_core::domain::FailureCode::Busy)
    );
    assert_eq!(report.records_committed, 0);
    assert_vfs_no_mutations()?;
    writer.command("release", "RELEASED")?;
    writer.stop()?;
    Ok(())
}

#[test]
fn sqlite_hot_journal_writer_child_entrypoint() -> TestResult {
    let Ok(path) = std::env::var("QUOTERN_OPENCODE_JOURNAL_WRITER") else {
        return Ok(());
    };
    let connection = Connection::open(path)?;
    let mode: String = connection.query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))?;
    assert_eq!(mode, "delete");
    connection.execute_batch(
        "CREATE TABLE records(id TEXT PRIMARY KEY);\
         BEGIN EXCLUSIVE;\
         INSERT INTO records VALUES ('uncommitted');",
    )?;
    println!("JOURNAL_READY");
    std::io::stdout().flush()?;
    if let Some(command) = std::io::stdin().lock().lines().next() {
        match command?.as_str() {
            "exit" => {
                drop(connection);
                println!("CLOSED");
                std::io::stdout().flush()?;
            }
            other => return Err(format!("unknown journal writer command: {other}").into()),
        }
    }
    Ok(())
}

fn start_journal_writer(path: &Path) -> TestResult<WriterChild> {
    WriterChild::spawn(
        "sqlite_hot_journal_writer_child_entrypoint",
        &[("QUOTERN_OPENCODE_JOURNAL_WRITER", path.as_os_str())],
        "JOURNAL_READY",
    )
}

#[test]
fn spike_s6_hot_journal_is_refused_before_sqlite_open() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let database = source.join("opencode.db");
    let mut writer = start_journal_writer(&database)?;
    let journal = PathBuf::from(format!("{}-journal", database.display()));
    assert!(journal.exists());
    let before = source_image(&database)?;

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let (keys, probe) = (
        kernel::source_keys(&database)?,
        kernel::SyscallProbe::start()?,
    );
    let fs = quotern_core::ingest::fs::RecordingFs::new();
    let observed = fs.clone();
    let mut engine = open_recording_engine(fs, &source, &data, &home)
        .map_err(|report| format!("OpenCode engine failed: {report:?}"))?;
    let report = engine.pass(consented(), 6);
    assert_eq!(
        report.outcome,
        quotern_core::domain::PassOutcome::Unavailable
    );
    assert_eq!(
        report.failure,
        Some(quotern_core::domain::FailureCode::HotJournal)
    );
    assert_eq!(observed.metrics().sqlite_opens, 0);
    assert_source_unchanged(&database, &before)?;
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        // The hot journal is a source file too: the pass was refused before SQLite opened
        // anything, so the parent chain saw no source open or map, and this process holds no
        // source descriptor at all (the child writer owns the only ones).
        assert!(keys[kernel::JOURNAL].is_some());
        let held = kernel::live_source_fds(&keys)?;
        assert!(held.is_empty(), "{held:?}");
        let events = probe.finish()?;
        assert!(events.errors.is_empty(), "{:?}", events.errors);
        for kind in [kernel::DB, kernel::WAL, kernel::SHM, kernel::JOURNAL] {
            assert!(
                events.opens_of(&keys, kind).is_empty(),
                "{kind}: {events:?}"
            );
        }
        assert!(
            events
                .maps
                .iter()
                .all(|map| kernel::kind_of(&keys, map.identity).is_none())
        );
        events.readonly_open_oracle(&keys)?;
    }
    writer.crash()?;
    Ok(())
}
#[test]
fn spike_s7_readonly_directory_without_sidecars_creates_none() -> TestResult {
    use std::os::unix::fs::PermissionsExt;

    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let database = source.join("opencode.db");
    let mut writer = start_writer(&database)?;
    writer.stop()?;
    let before = source_image(&database)?;
    assert!(before[1].1.is_none());
    assert!(before[2].1.is_none());

    let original_permissions = std::fs::metadata(&source)?.permissions();
    let mut readonly_permissions = original_permissions.clone();
    readonly_permissions.set_mode(original_permissions.mode() & !0o222);
    std::fs::set_permissions(&source, readonly_permissions)?;
    let run_result: TestResult<_> = (|| {
        let fs = quotern_core::ingest::fs::RecordingFs::new();
        let observed = fs.clone();
        let mut engine = open_recording_engine(fs, &source, &data, &home)
            .map_err(|report| format!("OpenCode engine failed: {report:?}"))?;
        let report = engine.pass(consented(), 7);
        Ok((report, observed.metrics(), source_image(&database)?))
    })();
    std::fs::set_permissions(&source, original_permissions)?;
    let (report, metrics, after) = run_result?;
    assert_eq!(
        report.outcome,
        quotern_core::domain::PassOutcome::Unavailable
    );
    assert_eq!(
        report.failure,
        Some(quotern_core::domain::FailureCode::SourceIdle)
    );
    assert_eq!(metrics.sqlite_opens, 0);
    assert_eq!(after, before);
    Ok(())
}
#[test]
fn spike_r_sidecars_removed_after_preflight_are_never_recreated() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, _data, _home) = source_roots(directory.path())?;
    let database = source.join("opencode.db");
    let mut writer = start_writer(&database)?;
    writer.crash()?;
    let canonical = database.canonicalize()?;
    let wal = PathBuf::from(format!("{}-wal", database.display()));
    let shm = PathBuf::from(format!("{}-shm", database.display()));
    let wal_image = std::fs::read(&wal)?;
    let shm_image = std::fs::read(&shm)?;
    let database_image = std::fs::read(&database)?;
    let mut oracle_rows = 0;
    let mut unavailable = 0;

    for attempt in 0..200 {
        if attempt > 0 {
            std::fs::write(&wal, &wal_image)?;
            std::fs::write(&shm, &shm_image)?;
        }
        let mut counters = quotern_core::domain::PassCounters::default();
        let identity = quotern_core::ingest::sqlite_ro::preflight(
            &quotern_core::ingest::fs::RealSourceFs,
            &canonical,
            &mut counters,
        )
        .map_err(|failure| format!("race preflight failed: {failure:?}"))?;
        assert!(identity.wal.exists && identity.shm.exists);
        assert_eq!(counters.header_reads, 1);

        std::fs::remove_file(&wal)?;
        std::fs::remove_file(&shm)?;
        reset_vfs_metrics()?;
        match open_canonical(&canonical) {
            Ok(connection) => {
                match connection.query_row("SELECT COUNT(*) FROM session_message", [], |row| {
                    row.get::<_, i64>(0)
                }) {
                    Ok(rows) => {
                        assert_eq!(rows, 1, "an inconsistent preflight/open race returned rows");
                        oracle_rows += 1;
                    }
                    Err(rusqlite::Error::SqliteFailure(_, _)) => unavailable += 1,
                    Err(error) => return Err(error.into()),
                }
            }
            Err(quotern_core::ingest::sqlite_ro::OpenError::Sqlite(_)) => unavailable += 1,
            Err(error) => return Err(error.into()),
        }
        assert!(
            !wal.exists(),
            "SQLite recreated the WAL in attempt {attempt}"
        );
        assert!(
            !shm.exists(),
            "SQLite recreated shared memory in attempt {attempt}"
        );
        assert_eq!(std::fs::read(&database)?, database_image);
        assert_vfs_no_mutations()?;
    }
    assert_eq!(oracle_rows + unavailable, 200);
    println!("R attempts=200 oracle_rows={oracle_rows} unavailable={unavailable}");
    Ok(())
}

fn file_tree_image(root: &Path) -> std::io::Result<Vec<(PathBuf, Vec<u8>)>> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let kind = entry.file_type()?;
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?
                    .to_path_buf();
                files.push((relative, std::fs::read(path)?));
            }
        }
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(files)
}

#[test]
fn spike_h_hostile_uri_paths_open_only_the_canonical_database() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, _home) = source_roots(directory.path())?;
    let components = [
        "question?mark",
        "hash#",
        "percent%",
        "ampersand&",
        "equals=",
        "space dir",
        "rÃ©pertoire",
        "x?mode=rwc&vfs=unix",
    ];
    let mut databases = Vec::new();
    for component in components {
        let parent = source.join(component);
        std::fs::create_dir(&parent)?;
        let database = parent.join("opencode.db");
        let writer = Connection::open(&database)?;
        writer.execute_batch(
            "CREATE TABLE records(id TEXT PRIMARY KEY); INSERT INTO records VALUES ('oracle');",
        )?;
        drop(writer);
        databases.push(database);
    }
    let before = file_tree_image(directory.path())?;
    reset_vfs_metrics()?;

    for database in &databases {
        let canonical = database.canonicalize()?;
        let reader = open_canonical(&canonical)?;
        let opened_path: String = reader.query_row("PRAGMA database_list", [], |row| row.get(2))?;
        assert_eq!(
            opened_path,
            canonical.to_str().expect("fixture path is UTF-8")
        );
        let row: String = reader.query_row("SELECT id FROM records", [], |row| row.get(0))?;
        assert_eq!(row, "oracle");
    }
    assert_eq!(file_tree_image(directory.path())?, before);
    assert!(!data.exists(), "source open created an app-data copy");
    assert_vfs_no_mutations()?;
    println!("H hostile_paths={}", databases.len());
    Ok(())
}
/// Complete OpenCode fixture in rollback-journal mode. An in-process WAL writer would share one
/// writable shared-memory node with the reader, which the read-only VFS refuses by design, so
/// live-WAL behavior is covered with out-of-process writers instead.
fn open_fixture(path: &Path) -> TestResult<Connection> {
    let connection = Connection::open(path)?;
    connection.execute_batch(include_str!(
        "../../../Fixtures/harness/opencode/wal/schema.sql"
    ))?;
    let mode: String = connection.query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))?;
    assert_eq!(mode, "delete");
    Ok(connection)
}

fn seed_wal_fixture(connection: &Connection) -> TestResult {
    let rows: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../Fixtures/harness/opencode/wal/rows.json"
    ))?;
    for message in rows["legacy_messages"]
        .as_array()
        .expect("legacy message fixture array")
    {
        let data = serde_json::to_vec(&message["data"])?;
        connection.execute(
            "INSERT INTO message(id, session_id, time_created, data) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                message["id"].as_str().expect("legacy id"),
                message["session_id"].as_str().expect("legacy session"),
                message["time_created"].as_i64(),
                data,
            ],
        )?;
    }
    for part in rows["legacy_parts"]
        .as_array()
        .expect("legacy part fixture array")
    {
        let data = serde_json::to_vec(&part["data"])?;
        connection.execute(
            "INSERT INTO part(id, message_id, session_id, time_created, data) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                part["id"].as_str().expect("part id"),
                part["message_id"].as_str().expect("part message"),
                part["session_id"].as_str().expect("part session"),
                part["time_created"].as_i64(),
                data,
            ],
        )?;
    }
    for message in rows["v2_messages"]
        .as_array()
        .expect("v2 message fixture array")
    {
        let session_id = message["session_id"].as_str().expect("v2 session");
        let data = serde_json::to_vec(&message["data"])?;
        connection.execute(
            "INSERT OR IGNORE INTO session_v2(id) VALUES (?1)",
            [session_id],
        )?;
        connection.execute(
            "INSERT INTO session_message(id, session_id, type, seq, time_created, data) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                message["id"].as_str().expect("v2 id"),
                session_id,
                message["type"].as_str().expect("v2 type"),
                message["seq"].as_i64().expect("v2 sequence"),
                message["time_created"].as_i64(),
                data,
            ],
        )?;
    }
    Ok(())
}

fn wal_expected() -> TestResult<serde_json::Value> {
    Ok(serde_json::from_slice(include_bytes!(
        "../../../Fixtures/harness/opencode/wal/expected.json"
    ))?)
}

fn assert_wal_record(
    observation: &quotern_core::domain::SourceReportedObservation,
    expected: &serde_json::Value,
) {
    assert_eq!(
        observation.session_id,
        expected["session_id"].as_str().unwrap()
    );
    assert_eq!(
        observation.message_id,
        expected["message_id"].as_str().unwrap()
    );
    assert_eq!(observation.input.value, expected["input"].as_u64());
    assert_eq!(observation.output.value, expected["output"].as_u64());
    assert_eq!(observation.reasoning.value, expected["reasoning"].as_u64());
    assert_eq!(
        observation.cache_read.value,
        expected["cache_read"].as_u64()
    );
    assert_eq!(
        observation.cache_write.value,
        expected["cache_write"].as_u64()
    );
    assert_eq!(observation.total.value, expected["total"].as_u64());
    if let Some(provenance) = expected["provenance"].as_str() {
        let provenance = match provenance {
            "reported" => Some(quotern_core::domain::Provenance::Reported),
            "derived" => Some(quotern_core::domain::Provenance::Derived),
            other => panic!("unknown independent provenance {other}"),
        };
        assert_eq!(observation.total.provenance, provenance);
    }
    if let Some(convention) = expected["source_convention"].as_str() {
        assert_eq!(observation.source_convention.as_deref(), Some(convention));
    }
    if let Some(mismatch) = expected["total_mismatch"].as_bool() {
        assert_eq!(observation.total_mismatch, mismatch);
    }
    if let Some(parts) = expected["selected_part_ids"].as_array() {
        let parts = parts
            .iter()
            .map(|part| part.as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(observation.selected_part_ids, parts);
    }
}

fn wal_engine_roots(base: &Path) -> TestResult<(PathBuf, PathBuf, PathBuf)> {
    let source = base.join("source");
    let data = base.join("data");
    let home = base.join("home");
    std::fs::create_dir(&source)?;
    std::fs::create_dir(&home)?;
    Ok((source, data, home))
}

#[test]
fn part_group_replaces_parent() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = wal_engine_roots(directory.path())?;
    let database = source.join("opencode.db");
    let writer = open_fixture(&database)?;
    seed_wal_fixture(&writer)?;
    let mut engine = open_engine(&source, &data, &home)?;
    let report = engine.pass(consented(), 1);
    assert_eq!(
        report.outcome,
        quotern_core::domain::PassOutcome::Consistent
    );
    assert_eq!(report.records_committed, 6);

    let expected = wal_expected()?;
    let observations = engine.observations()?;
    assert_eq!(
        observations.len(),
        expected["counts"]["initial_records"].as_u64().unwrap() as usize
    );
    for expected_record in expected["records"].as_array().unwrap() {
        let message_id = expected_record["message_id"].as_str().unwrap();
        let observation = observations
            .iter()
            .find(|record| record.message_id == message_id)
            .expect("fixture record acquired");
        assert_wal_record(observation, expected_record);
    }
    let group = observations
        .iter()
        .find(|record| record.message_id == "part-parent")
        .expect("part parent acquired");
    assert_eq!(group.total.value, Some(100));
    assert_eq!(group.selected_part_ids, ["p1", "p2"]);
    assert!(!group.pending_partial);
    Ok(())
}
#[test]
fn reported_revision_restart_prune() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = wal_engine_roots(directory.path())?;
    let database = source.join("opencode.db");
    let writer = open_fixture(&database)?;
    seed_wal_fixture(&writer)?;
    let mut engine = open_engine(&source, &data, &home)?;

    let initial = engine.pass(consented(), 1);
    assert_eq!(
        initial.outcome,
        quotern_core::domain::PassOutcome::Consistent
    );
    let original = engine
        .observations()?
        .into_iter()
        .find(|record| record.message_id == "same-id")
        .expect("fixture record acquired");
    assert_eq!(original.total.value, Some(100));
    assert_eq!(original.revision, 1);

    let revised_payload = serde_json::to_vec(&serde_json::json!({
        "role": "assistant",
        "tokens": {
            "input": 101,
            "output": 0,
            "reasoning": 0,
            "cache": {"read": 0, "write": 0},
            "total": 101
        }
    }))?;
    writer.execute(
        "UPDATE message SET data = ?1 WHERE id = 'same-id' AND session_id = 'session-a'",
        [revised_payload],
    )?;
    let revised = engine.pass(consented(), 2);
    assert_eq!(
        revised.outcome,
        quotern_core::domain::PassOutcome::Consistent
    );
    let revised_record = engine
        .observations()?
        .into_iter()
        .find(|record| record.message_id == "same-id")
        .expect("revised record retained");
    assert_eq!(revised_record.total.value, Some(101));
    assert_eq!(revised_record.revision, 2);
    drop(engine);

    let mut engine = open_engine(&source, &data, &home)?;
    let reopened = engine.pass(consented(), 3);
    assert_eq!(
        reopened.outcome,
        quotern_core::domain::PassOutcome::Consistent
    );
    let stable_record = engine
        .observations()?
        .into_iter()
        .find(|record| record.message_id == "same-id")
        .expect("reopened record retained");
    assert_eq!(stable_record.total.value, Some(101));
    assert_eq!(stable_record.revision, 2);

    writer.execute(
        "DELETE FROM message WHERE id = 'legacy-derived' AND session_id = 'session-a'",
        [],
    )?;
    let pruned_source = engine.pass(consented(), 4);
    assert_eq!(
        pruned_source.outcome,
        quotern_core::domain::PassOutcome::Consistent
    );
    let history = engine.observations()?;
    assert_eq!(history.len(), 6);
    let revised_history = history
        .iter()
        .find(|record| record.message_id == "same-id")
        .expect("revised history survives source restart");
    assert_eq!(revised_history.total.value, Some(101));
    assert_eq!(revised_history.revision, 2);
    let absent_history = history
        .iter()
        .find(|record| record.message_id == "legacy-derived")
        .expect("source omission does not erase reported history");
    assert_eq!(absent_history.total.value, Some(42));
    assert_eq!(absent_history.revision, 1);
    Ok(())
}

#[test]
fn pruned_part_retains_complete_group() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = wal_engine_roots(directory.path())?;
    let database = source.join("opencode.db");
    let writer = open_fixture(&database)?;
    seed_wal_fixture(&writer)?;
    let steps: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../Fixtures/harness/opencode/wal/steps.json"
    ))?;
    let mut engine = open_engine(&source, &data, &home)?;

    assert_eq!(
        engine.pass(consented(), 1).outcome,
        quotern_core::domain::PassOutcome::Consistent
    );
    writer.execute(
        "DELETE FROM part WHERE id = 'p2' AND message_id = 'part-parent'",
        [],
    )?;
    let report = engine.pass(consented(), 2);
    assert_eq!(report.outcome, quotern_core::domain::PassOutcome::Partial);
    let observations = engine.observations()?;
    assert_eq!(observations.len(), 6);
    let group = observations
        .iter()
        .find(|record| record.message_id == "part-parent")
        .expect("complete prior group retained");
    assert_eq!(group.total.value, steps[1]["expected_total"].as_u64());
    assert_eq!(group.selected_part_ids, ["p1", "p2"]);
    assert_eq!(group.revision, 1);
    assert!(group.pending_partial);
    assert_eq!(
        group.total.status,
        quotern_core::domain::ObservationStatus::Partial
    );
    Ok(())
}

#[test]
fn explicit_zero_part_corrects_group() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = wal_engine_roots(directory.path())?;
    let database = source.join("opencode.db");
    let writer = open_fixture(&database)?;
    seed_wal_fixture(&writer)?;
    let steps: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../Fixtures/harness/opencode/wal/steps.json"
    ))?;
    let mut engine = open_engine(&source, &data, &home)?;

    assert_eq!(
        engine.pass(consented(), 1).outcome,
        quotern_core::domain::PassOutcome::Consistent
    );
    let zero_part = serde_json::to_vec(&serde_json::json!({
        "type": "step-finish",
        "cost": 0,
        "tokens": {
            "input": 0,
            "output": 0,
            "reasoning": 0,
            "cache": {"read": 0, "write": 0},
            "total": 0
        }
    }))?;
    writer.execute(
        "UPDATE part SET data = ?1 WHERE id = 'p2' AND message_id = 'part-parent'",
        [zero_part],
    )?;
    let corrected = engine.pass(consented(), 2);
    assert_eq!(
        corrected.outcome,
        quotern_core::domain::PassOutcome::Consistent
    );
    let group = engine
        .observations()?
        .into_iter()
        .find(|record| record.message_id == "part-parent")
        .expect("corrected part group");
    assert_eq!(group.total.value, steps[2]["expected_total"].as_u64());
    assert_eq!(group.selected_part_ids, ["p1", "p2"]);
    assert_eq!(group.revision, 2);
    assert!(!group.pending_partial);
    assert_eq!(
        group.total.provenance,
        Some(quotern_core::domain::Provenance::Reported)
    );
    Ok(())
}
#[test]
fn json_message_part_only_mutation() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = wal_engine_roots(directory.path())?;
    let message = source.join("storage/message/session-json/part-only.json");
    let parts = source.join("storage/part/part-only");
    std::fs::create_dir_all(message.parent().expect("message parent"))?;
    std::fs::create_dir_all(&parts)?;
    std::fs::write(
        &message,
        serde_json::to_vec(&serde_json::json!({
            "role": "assistant",
            "time": {"created": 1700000000000_i64},
            "content": "Parent usage is absent; completed part is reported."
        }))?,
    )?;
    let part = parts.join("p1.json");
    let part_payload = |input, output| {
        serde_json::to_vec(&serde_json::json!({
            "type": "step-finish",
            "cost": 0,
            "tokens": {
                "input": input,
                "output": output,
                "reasoning": 3,
                "cache": {"read": 4, "write": 3},
                "total": input + output + 10
            }
        }))
    };
    std::fs::write(&part, part_payload(10_u64, 20_u64)?)?;
    let mut engine = open_engine(&source, &data, &home)?;

    let initial = engine.pass(consented(), 1);
    assert_eq!(
        initial.outcome,
        quotern_core::domain::PassOutcome::Consistent
    );
    let first = engine
        .observations()?
        .into_iter()
        .find(|record| record.message_id == "part-only")
        .expect("parts-only JSON record acquired");
    assert_eq!(first.input.value, Some(10));
    assert_eq!(first.output.value, Some(20));
    assert_eq!(first.total.value, Some(40));
    assert_eq!(first.selected_part_ids, ["p1"]);
    assert_eq!(first.revision, 1);

    std::fs::write(&part, part_payload(0_u64, 0_u64)?)?;
    let revised = engine.pass(consented(), 2);
    assert_eq!(
        revised.outcome,
        quotern_core::domain::PassOutcome::Consistent
    );
    let updated = engine
        .observations()?
        .into_iter()
        .find(|record| record.message_id == "part-only")
        .expect("revised parts-only record");
    assert_eq!(updated.input.value, Some(0));
    assert_eq!(updated.output.value, Some(0));
    assert_eq!(updated.total.value, Some(10));
    assert_eq!(updated.selected_part_ids, ["p1"]);
    assert_eq!(updated.revision, 2);
    Ok(())
}

#[test]
fn malformed_schema_is_not_empty_success() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = wal_engine_roots(directory.path())?;
    let database = source.join("opencode.db");
    let writer = Connection::open(&database)?;
    writer.execute_batch(
        "CREATE TABLE session_message(\
            id TEXT NOT NULL, session_id TEXT NOT NULL, type TEXT NOT NULL,\
            seq INTEGER NOT NULL, time_created INTEGER, data BLOB NOT NULL,\
            PRIMARY KEY(id, session_id)\
        );",
    )?;
    drop(writer);
    let mut engine = open_engine(&source, &data, &home)?;
    let report = engine.pass(consented(), 1);
    assert_eq!(
        report.outcome,
        quotern_core::domain::PassOutcome::Unavailable
    );
    assert_eq!(
        report.failure,
        Some(quotern_core::domain::FailureCode::UnsupportedSchema)
    );
    assert_eq!(report.records_committed, 0);
    assert_eq!(engine.observations()?.len(), 0);
    assert!(report.counters.source_opens > 0);
    assert!(report.counters.header_reads > 0);
    Ok(())
}
fn insert_legacy_mirror(source: &Path, name: &str) -> TestResult<Connection> {
    let writer = open_fixture(&source.join(name))?;
    let same_id_total = if name == "opencode-a.db" { 100 } else { 101 };
    let same_id_payload = serde_json::to_vec(&serde_json::json!({
        "role": "assistant",
        "tokens": {
            "input": 100,
            "output": 0,
            "reasoning": 0,
            "cache": {"read": 0, "write": 0},
            "total": same_id_total
        }
    }))?;
    writer.execute(
        "INSERT INTO message(id, session_id, time_created, data) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![
            "same-id",
            "mirror-session",
            1_700_000_000_000_i64,
            same_id_payload
        ],
    )?;
    if name == "opencode-z.db" {
        let regenerated_payload = serde_json::to_vec(&serde_json::json!({
            "role": "assistant",
            "tokens": {
                "input": 100,
                "output": 0,
                "reasoning": 0,
                "cache": {"read": 0, "write": 0},
                "total": 100
            }
        }))?;
        writer.execute(
            "INSERT INTO message(id, session_id, time_created, data) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                "regenerated-copy",
                "mirror-session",
                1_700_000_000_000_i64,
                regenerated_payload
            ],
        )?;
    }
    Ok(writer)
}

fn write_json_mirror(source: &Path) -> TestResult {
    let message = source.join("storage/message/mirror-session/same-id.json");
    std::fs::create_dir_all(message.parent().expect("JSON message parent"))?;
    std::fs::write(
        message,
        serde_json::to_vec(&serde_json::json!({
            "role": "assistant",
            "time": {"created": 1700000000000_i64},
            "tokens": {
                "input": 5,
                "output": 0,
                "reasoning": 0,
                "cache": {"read": 0, "write": 0},
                "total": 5
            }
        }))?,
    )?;
    Ok(())
}

fn assert_mirror_observations(
    engine: &quotern_core::ingest::OpenCodeEngine<quotern_core::ingest::fs::RealSourceFs>,
    expected_total: u64,
) -> TestResult {
    let records = engine.observations()?;
    assert_eq!(records.len(), 2);
    let same_id = records
        .iter()
        .find(|record| record.message_id == "same-id")
        .expect("same-ID mirrors resolve to one observation");
    assert_eq!(same_id.total.value, Some(100));
    assert!(same_id.mirror_conflict);
    let regenerated = records
        .iter()
        .find(|record| record.message_id == "regenerated-copy")
        .expect("regenerated identity remains a distinct observation");
    assert_eq!(regenerated.total.value, Some(100));
    assert!(!regenerated.mirror_conflict);
    assert!(records.iter().all(|record| record.revision == 1));
    let wire = serde_json::to_value(&records)?;
    assert!(
        wire.as_array()
            .expect("serialized observations are an array")
            .iter()
            .all(|record| record.get("verified_consumption").is_none())
    );
    assert!(records.iter().all(|record| {
        record.origin_uncertainty == quotern_core::domain::OriginUncertainty::UnverifiedOrigin
    }));
    let reported_total = records
        .iter()
        .filter_map(|record| record.total.value)
        .sum::<u64>();
    assert_eq!(reported_total, expected_total);
    Ok(())
}

fn run_mirror_scenario(base: &Path, creation_order: &[&str]) -> TestResult<Vec<MirrorObservation>> {
    let (source, data, home) = wal_engine_roots(base)?;
    let mut writers = Vec::new();
    for name in creation_order {
        writers.push(insert_legacy_mirror(&source, name)?);
    }
    write_json_mirror(&source)?;
    let expected = wal_expected()?;
    assert_eq!(expected["same_id_mirror_count"].as_u64(), Some(1));
    assert_eq!(
        expected["regenerated_id_copy_reported_total"].as_u64(),
        Some(200)
    );
    assert!(expected["verified_consumption"].is_null());

    let mut engine = open_engine(&source, &data, &home)?;
    for now_ms in [1, 2] {
        let report = engine.pass(consented(), now_ms);
        assert_eq!(
            report.outcome,
            quotern_core::domain::PassOutcome::Consistent
        );
        assert_mirror_observations(
            &engine,
            expected["regenerated_id_copy_reported_total"]
                .as_u64()
                .expect("reported total oracle"),
        )?;
        if now_ms == 1 {
            drop(engine);
            engine = open_engine(&source, &data, &home)?;
        }
    }
    let records = engine.observations()?;
    let mut summary = records
        .into_iter()
        .map(|record| {
            (
                record.message_id,
                record.total.value,
                record.mirror_conflict,
                record.revision,
            )
        })
        .collect::<Vec<_>>();
    summary.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(summary)
}

#[test]
fn same_id_mirrors_order_independent() -> TestResult {
    let _guard = vfs_test_guard();
    let first = tempdir()?;
    let second = tempdir()?;
    let forward = run_mirror_scenario(first.path(), &["opencode-z.db", "opencode-a.db"])?;
    let reverse = run_mirror_scenario(second.path(), &["opencode-a.db", "opencode-z.db"])?;
    assert_eq!(forward, reverse);
    assert_eq!(
        forward,
        [
            ("regenerated-copy".to_owned(), Some(100), false, 1),
            ("same-id".to_owned(), Some(100), true, 1)
        ]
    );
    Ok(())
}

#[test]
fn mirror_rank_path_restart_and_tie() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let records = run_mirror_scenario(directory.path(), &["opencode-z.db", "opencode-a.db"])?;
    let same_id = records
        .iter()
        .find(|record| record.0 == "same-id")
        .expect("same-ID observation");
    assert_eq!(same_id.1, Some(100));
    assert!(same_id.2);

    let path = PathBuf::from("/source/opencode.db");
    let decode = |input| {
        let payload = serde_json::to_vec(&serde_json::json!({
            "role": "assistant",
            "tokens": {
                "input": input,
                "output": 0,
                "reasoning": 0,
                "cache": {"read": 0, "write": 0},
                "total": input
            }
        }))
        .expect("test payload serializes");
        quotern_core::adapters::opencode::decode_record(
            "session",
            "same-path",
            Some(1_700_000_000_000),
            None,
            &payload,
            &path,
            0,
        )
        .expect("valid competing source observation")
    };
    let first = decode(1_u64);
    let second = decode(2_u64);
    for candidates in [vec![first.clone(), second.clone()], vec![second, first]] {
        assert_eq!(
            quotern_core::adapters::opencode::resolve_candidates(candidates),
            Err(quotern_core::adapters::opencode::ResolveError::SourceChanging)
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Source-effect, mapping and hostile-file oracles
// ---------------------------------------------------------------------------------------------

use quotern_core::domain::{FailureCode, PassOutcome, PassReport};
use quotern_core::ingest::OpenCodeEngine;
use quotern_core::ingest::fs::{OpenKind, RecordingFs};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::time::Duration;

/// Everything a hostile `chmod`/`chown`/`touch` would change, read independently of the VFS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Meta {
    mode: u32,
    uid: u32,
    gid: u32,
    ctime: (i64, i64),
    mtime: (i64, i64),
    size: u64,
    inode: u64,
}

fn meta(path: &Path) -> TestResult<Meta> {
    let metadata = std::fs::metadata(path)?;
    Ok(Meta {
        mode: metadata.mode() & 0o7777,
        uid: metadata.uid(),
        gid: metadata.gid(),
        ctime: (metadata.ctime(), metadata.ctime_nsec()),
        mtime: (metadata.mtime(), metadata.mtime_nsec()),
        size: metadata.len(),
        inode: metadata.ino(),
    })
}

fn sidecar(database: &Path, suffix: &str) -> PathBuf {
    PathBuf::from(format!("{}{suffix}", database.display()))
}

/// Seeds the complete fixture in rollback mode, then returns a child holding it open in WAL mode.
fn live_fixture(database: &Path) -> TestResult<WriterChild> {
    let seed = open_fixture(database)?;
    seed_wal_fixture(&seed)?;
    drop(seed);
    start_existing_writer(database)
}

/// Runs one pass on a worker thread and fails the test if it does not finish in time.
fn pass_within<F>(
    engine: OpenCodeEngine<F>,
    now_ms: i64,
    seconds: u64,
) -> TestResult<(OpenCodeEngine<F>, PassReport)>
where
    F: quotern_core::ingest::fs::SourceFs + Send + 'static,
{
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut engine = engine;
        let report = engine.pass(consented(), now_ms);
        let _ = sender.send((engine, report));
    });
    receiver
        .recv_timeout(Duration::from_secs(seconds))
        .map_err(|error| format!("pass did not finish within {seconds}s: {error}").into())
}

fn run_until_consistent<F: quotern_core::ingest::fs::SourceFs>(
    engine: &mut OpenCodeEngine<F>,
    first_ms: i64,
    limit: usize,
) -> Vec<PassReport> {
    let mut reports = Vec::new();
    for step in 0..limit {
        let report = engine.pass(consented(), first_ms + step as i64 * 60_000);
        let done = report.outcome == PassOutcome::Consistent;
        reports.push(report);
        if done {
            break;
        }
    }
    reports
}

#[test]
fn empty_wal_mode_mismatch_is_not_changed_by_acquisition() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let database = source.join("opencode.db");
    let mut holder = live_fixture(&database)?;
    // Leave an empty WAL (all frames checkpointed) whose mode differs from the database's: the
    // Unix parent would `fchmod` it to the database mode on open.
    holder.exec("PRAGMA wal_checkpoint(TRUNCATE);")?;
    let wal = sidecar(&database, "-wal");
    let shm = sidecar(&database, "-shm");
    assert_eq!(
        std::fs::metadata(&wal)?.len(),
        0,
        "probe needs an empty WAL"
    );
    assert!(
        std::fs::metadata(&shm)?.len() >= 32 * 1024,
        "probe needs initialized SHM"
    );
    std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o644))?;
    std::fs::set_permissions(&wal, std::fs::Permissions::from_mode(0o600))?;

    // Negative control: reading through the unmodified parent VFS really does change the mode,
    // so the metadata oracle is able to see the effect it forbids.
    let before_control = meta(&wal)?;
    let probe = VfsProbe::new("quotern-metadata-control")?;
    let uri = format!(
        "file:{}?mode=ro&readonly_shm=1",
        database.canonicalize()?.display()
    );
    let reader = Connection::open_with_flags_and_vfs(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        probe.name().as_c_str(),
    )?;
    let rows: i64 = reader.query_row("SELECT COUNT(*) FROM message", [], |row| row.get(0))?;
    assert_eq!(rows, 4);
    drop(reader);
    let after_control = meta(&wal)?;
    assert_eq!(before_control.mode, 0o600);
    assert_eq!(
        after_control.mode, 0o644,
        "control: the delegating VFS changes empty-WAL permissions"
    );
    std::fs::set_permissions(&wal, std::fs::Permissions::from_mode(0o600))?;

    let files = [database.clone(), wal.clone(), shm.clone()];
    let before = files
        .iter()
        .map(|path| meta(path))
        .collect::<Result<Vec<_>, _>>()?;
    let image = source_image(&database)?;
    reset_vfs_metrics()?;
    let mut engine = open_engine(&source, &data, &home)?;
    let report = engine.pass(consented(), 1_700_000_001_000);
    assert_eq!(report.outcome, PassOutcome::Consistent, "{report:?}");
    assert_eq!(report.records_committed, 6);
    let after = files
        .iter()
        .map(|path| meta(path))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        before, after,
        "mode, owner, ctime, mtime, size and inode are untouched"
    );
    assert_eq!(meta(&wal)?.mode, 0o600);
    assert_source_unchanged(&database, &image)?;

    let metrics = vfs_metrics()?;
    assert_eq!(
        metrics.effective_write_capable_descriptors, 0,
        "{metrics:?}"
    );
    assert_eq!(metrics.nonregular_descriptors_rejected, 0, "{metrics:?}");
    assert!(metrics.descriptors_verified > 0, "{metrics:?}");
    // An empty WAL needs no wal-index page, so no mapping is expected here; none may be writable.
    assert_eq!(
        metrics.unverified_shared_memory_maps_rejected, 0,
        "{metrics:?}"
    );
    assert_eq!(
        metrics.writable_shared_memory_maps_rejected, 0,
        "{metrics:?}"
    );
    assert_vfs_no_mutations()?;
    holder.stop()?;
    Ok(())
}

#[test]
fn same_process_writable_shared_memory_fails_closed() -> TestResult {
    let _guard = vfs_test_guard();
    // Registering the VFS first guarantees the writer's mapping is observed as writable.
    reset_vfs_metrics()?;
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let database = source.join("opencode.db");
    let writer = open_fixture(&database)?;
    seed_wal_fixture(&writer)?;
    let mode: String = writer.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
    assert_eq!(mode, "wal");
    writer.pragma_update(None, "wal_autocheckpoint", 0)?;
    writer.execute("DELETE FROM part WHERE id = 'none'", [])?;
    writer.execute("UPDATE message SET time_created = time_created", [])?;
    let image = source_image(&database)?;
    assert!(
        image[1].1.is_some() && image[2].1.is_some(),
        "live sidecars"
    );

    reset_vfs_metrics()?;
    let reader = open_canonical(&database.canonicalize()?)?;
    let error = reader
        .query_row("SELECT COUNT(*) FROM message", [], |row| {
            row.get::<_, i64>(0)
        })
        .expect_err("a writable in-process shared-memory node must not be reused");
    assert!(
        matches!(error, rusqlite::Error::SqliteFailure(..)),
        "{error:?}"
    );
    drop(reader);
    let metrics = vfs_metrics()?;
    assert!(
        metrics.writable_shared_memory_maps_rejected
            + metrics.unverified_shared_memory_maps_rejected
            > 0,
        "{metrics:?}"
    );
    assert_eq!(metrics.readonly_shared_memory_maps, 0, "{metrics:?}");
    assert_source_unchanged(&database, &image)?;

    // The engine reports the state as unavailable and keeps its history empty: no fallback.
    reset_vfs_metrics()?;
    let mut engine = open_engine(&source, &data, &home)?;
    let report = engine.pass(consented(), 1);
    assert_eq!(report.outcome, PassOutcome::Unavailable, "{report:?}");
    assert_eq!(report.failure, Some(FailureCode::Sqlite));
    assert_eq!(report.records_committed, 0);
    assert!(engine.observations()?.is_empty());
    assert_source_unchanged(&database, &image)?;
    drop(writer);
    Ok(())
}

fn mkfifo(path: &Path) -> TestResult {
    let status = std::process::Command::new("mkfifo").arg(path).status()?;
    assert!(status.success(), "mkfifo {}", path.display());
    Ok(())
}

#[test]
fn nonregular_sidecars_are_refused_without_blocking() -> TestResult {
    let _guard = vfs_test_guard();
    for suffix in ["-wal", "-shm", "-journal"] {
        let directory = tempdir()?;
        let (source, data, home) = source_roots(directory.path())?;
        let database = source.join("opencode.db");
        let seed = open_fixture(&database)?;
        seed_wal_fixture(&seed)?;
        let mode: String = seed.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        assert_eq!(mode, "wal");
        drop(seed);
        mkfifo(&sidecar(&database, suffix))?;
        let fs = RecordingFs::new();
        let observed = fs.clone();
        let engine = open_recording_engine(fs, &source, &data, &home)
            .map_err(|report| format!("open failed: {report:?}"))?;
        let (_engine, report) = pass_within(engine, 1, 10)?;
        assert_eq!(
            report.outcome,
            PassOutcome::Unavailable,
            "{suffix}: {report:?}"
        );
        assert!(
            matches!(
                report.failure,
                Some(FailureCode::Io | FailureCode::HotJournal)
            ),
            "{suffix}: {report:?}"
        );
        assert_eq!(observed.metrics().sqlite_opens, 0, "{suffix}");
    }
    Ok(())
}

#[test]
fn sidecar_replaced_by_fifo_after_preflight_is_refused_without_blocking() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let database = source.join("opencode.db");
    let mut holder = live_fixture(&database)?;
    let shm = sidecar(&database, "-shm");
    let parked = directory.path().join("shm.parked");
    let fs = RecordingFs::new();
    let swap_shm = shm.clone();
    let swap_parked = parked.clone();
    fs.on_boundary(move |kind, _| {
        if kind == OpenKind::Sqlite {
            // Between preflight and SQLite's own open of the sidecar.
            std::fs::rename(&swap_shm, &swap_parked).expect("park shm");
            let status = std::process::Command::new("mkfifo")
                .arg(&swap_shm)
                .status()
                .expect("mkfifo runs");
            assert!(status.success());
        }
    });
    let engine = open_recording_engine(fs, &source, &data, &home)
        .map_err(|report| format!("open failed: {report:?}"))?;
    let (_engine, report) = pass_within(engine, 1, 10)?;
    assert_eq!(report.outcome, PassOutcome::Unavailable, "{report:?}");
    assert_eq!(report.records_committed, 0);
    std::fs::remove_file(&shm)?;
    std::fs::rename(&parked, &shm)?;
    holder.stop()?;
    Ok(())
}

/// A JSON source with a message and one part, plus an outside directory holding a decoy.
fn json_source(base: &Path) -> TestResult<(PathBuf, PathBuf, PathBuf, PathBuf)> {
    let (source, data, home) = source_roots(&base.canonicalize()?)?;
    let message = source.join("storage/message/session-a/hostile.json");
    std::fs::create_dir_all(message.parent().ok_or("parent")?)?;
    std::fs::write(
        &message,
        serde_json::to_vec(&serde_json::json!({
            "role": "assistant", "time": {"created": 1_700_000_000_000_i64},
            "tokens": {"input": 1, "output": 2, "reasoning": 0, "cache": {"read": 0, "write": 0}}
        }))?,
    )?;
    Ok((source, data, home, message))
}

fn decoy_payload() -> TestResult<Vec<u8>> {
    Ok(serde_json::to_vec(&serde_json::json!({
        "role": "assistant", "time": {"created": 1_700_000_000_000_i64},
        "tokens": {"input": 77_777, "output": 0, "reasoning": 0, "cache": {"read": 0, "write": 0}}
    }))?)
}

#[test]
fn replaced_json_file_is_never_read_through_a_link_or_fifo() -> TestResult {
    let _guard = vfs_test_guard();
    for replacement in ["symlink", "fifo"] {
        let directory = tempdir()?;
        let (source, data, home, message) = json_source(directory.path())?;
        let outside = directory.path().join("outside.json");
        std::fs::write(&outside, decoy_payload()?)?;
        let fs = RecordingFs::new();
        let (target, outside_target, kind) = (message.clone(), outside.clone(), replacement);
        fs.on_boundary(move |open, path| {
            if open == OpenKind::Bounded && path == target {
                std::fs::remove_file(&target).expect("remove message");
                if kind == "symlink" {
                    std::os::unix::fs::symlink(&outside_target, &target).expect("symlink");
                } else {
                    mkfifo(&target).expect("fifo");
                }
            }
        });
        let engine = open_recording_engine(fs, &source, &data, &home)
            .map_err(|report| format!("open failed: {report:?}"))?;
        let (engine, report) = pass_within(engine, 1, 10)?;
        assert!(report.records_committed == 0, "{replacement}: {report:?}");
        assert!(
            engine
                .observations()?
                .iter()
                .all(|record| record.input.value != Some(77_777)),
            "{replacement}: outside data was read"
        );
        assert_ne!(
            report.outcome,
            PassOutcome::Consistent,
            "{replacement}: {report:?}"
        );
    }
    Ok(())
}

#[test]
fn ancestor_swapped_for_a_link_never_leaves_the_source_root() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home, _message) = json_source(directory.path())?;
    let outside = directory.path().join("outside");
    std::fs::create_dir_all(outside.join("message/session-a"))?;
    std::fs::write(
        outside.join("message/session-a/hostile.json"),
        decoy_payload()?,
    )?;
    let fs = RecordingFs::new();
    let (storage, parked, decoy) = (
        source.join("storage"),
        directory.path().join("storage.parked"),
        outside.clone(),
    );
    let trigger = source.join("storage/message");
    fs.on_boundary(move |open, path| {
        if open == OpenKind::Directory && path == trigger && storage.exists() && !parked.exists() {
            std::fs::rename(&storage, &parked).expect("park storage");
            std::os::unix::fs::symlink(&decoy, &storage).expect("symlink storage");
        }
    });
    let engine = open_recording_engine(fs, &source, &data, &home)
        .map_err(|report| format!("open failed: {report:?}"))?;
    let (engine, report) = pass_within(engine, 1, 10)?;
    assert!(
        engine
            .observations()?
            .iter()
            .all(|record| record.input.value != Some(77_777)),
        "{report:?}"
    );
    Ok(())
}

#[test]
fn aliased_application_store_is_rejected_before_any_write() -> TestResult {
    let _guard = vfs_test_guard();
    for alias in ["symlink", "hard-link", "wal-symlink"] {
        let directory = tempdir()?;
        let (source, data, home) = source_roots(directory.path())?;
        let database = source.join("opencode.db");
        let mut holder = live_fixture(&database)?;
        std::fs::create_dir_all(&data)?;
        match alias {
            "symlink" => std::os::unix::fs::symlink(&database, data.join("history.sqlite"))?,
            "hard-link" => std::fs::hard_link(&database, data.join("history.sqlite"))?,
            _ => std::os::unix::fs::symlink(
                sidecar(&database, "-wal"),
                data.join("history.sqlite-wal"),
            )?,
        }
        let image = source_image(&database)?;
        let metadata = [meta(&database)?, meta(&sidecar(&database, "-wal"))?];
        let report = match open_engine(&source, &data, &home) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("{alias}: aliased application store was accepted"),
        };
        assert!(
            report.contains("Store") || report.contains("store"),
            "{alias}: {report}"
        );
        assert_source_unchanged(&database, &image)?;
        assert_eq!(
            metadata,
            [meta(&database)?, meta(&sidecar(&database, "-wal"))?],
            "{alias}: source metadata"
        );
        holder.stop()?;
    }
    Ok(())
}

#[test]
fn application_store_replaced_after_open_is_not_written() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home, _message) = json_source(directory.path())?;
    let mut engine = open_engine(&source, &data, &home)?;
    assert_eq!(engine.pass(consented(), 1).outcome, PassOutcome::Consistent);
    let victim = directory.path().join("victim.sqlite");
    std::fs::write(&victim, b"not a store")?;
    let history = data.join("history.sqlite");
    std::fs::rename(&history, directory.path().join("history.moved"))?;
    std::os::unix::fs::symlink(&victim, &history)?;
    let report = engine.pass(consented(), 2);
    assert_eq!(report.failure, Some(FailureCode::Store), "{report:?}");
    assert_eq!(std::fs::read(&victim)?, b"not a store");
    Ok(())
}

#[test]
fn newer_or_corrupt_application_store_is_refused_untouched() -> TestResult {
    let _guard = vfs_test_guard();
    for variant in ["newer-rollback", "newer-wal-sidecar-free", "corrupt"] {
        let directory = tempdir()?;
        let (source, data, home) = source_roots(directory.path())?;
        std::fs::create_dir_all(&data)?;
        let history = data.join("history.sqlite");
        match variant {
            "corrupt" => std::fs::write(&history, vec![0x5a_u8; 4096])?,
            _ => {
                let connection = Connection::open(&history)?;
                connection
                    .execute_batch("CREATE TABLE future(id INTEGER); PRAGMA user_version = 99;")?;
            }
        }
        let before = file_tree_image(&data)?;
        let result = quotern_core::store::Store::open(&data);
        let expected = if variant == "corrupt" {
            quotern_core::store::StoreError::Corrupt
        } else {
            quotern_core::store::StoreError::UnsupportedVersion
        };
        assert_eq!(result.err(), Some(expected), "{variant}");
        assert_eq!(
            file_tree_image(&data)?,
            before,
            "{variant}: store bytes and sidecars"
        );
        assert!(open_engine(&source, &data, &home).is_err(), "{variant}");
        assert_eq!(file_tree_image(&data)?, before, "{variant}: engine startup");
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Acquisition semantics: counters, totals, envelopes
// ---------------------------------------------------------------------------------------------

use quotern_core::domain::{ObservationStatus, Provenance, SourceReportedObservation};
use serde_json::{Value, json};

const T0: i64 = 1_700_000_000_000;

fn counts(
    input: Option<u64>,
    output: Option<u64>,
    reasoning: Option<u64>,
    read: Option<u64>,
    write: Option<u64>,
    total: Option<u64>,
) -> Value {
    let mut tokens = serde_json::Map::new();
    for (key, value) in [
        ("input", input),
        ("output", output),
        ("reasoning", reasoning),
        ("total", total),
    ] {
        if let Some(value) = value {
            tokens.insert(key.to_owned(), json!(value));
        }
    }
    let mut cache = serde_json::Map::new();
    if let Some(read) = read {
        cache.insert("read".to_owned(), json!(read));
    }
    if let Some(write) = write {
        cache.insert("write".to_owned(), json!(write));
    }
    if !cache.is_empty() {
        tokens.insert("cache".to_owned(), Value::Object(cache));
    }
    Value::Object(tokens)
}

fn put_message(c: &Connection, id: &str, session: &str, time: i64, payload: &Value) -> TestResult {
    c.execute(
        "INSERT INTO message(id, session_id, time_created, data) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![id, session, time, serde_json::to_vec(payload)?],
    )?;
    Ok(())
}

fn put_part(c: &Connection, id: &str, message: &str, session: &str, payload: &Value) -> TestResult {
    c.execute(
        "INSERT INTO part(id, message_id, session_id, time_created, data) VALUES (?1, ?2, ?3, 1, ?4)",
        rusqlite::params![id, message, session, serde_json::to_vec(payload)?],
    )?;
    Ok(())
}

fn put_v2(
    c: &Connection,
    id: &str,
    session: &str,
    kind: &str,
    seq: i64,
    time: i64,
    payload: &Value,
) -> TestResult {
    c.execute(
        "INSERT OR IGNORE INTO session_v2(id) VALUES (?1)",
        [session],
    )?;
    c.execute(
        "INSERT INTO session_message(id, session_id, type, seq, time_created, data) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![id, session, kind, seq, time, serde_json::to_vec(payload)?],
    )?;
    Ok(())
}

fn step_finish(tokens: Value) -> Value {
    json!({"type": "step-finish", "tokens": tokens})
}

fn write_json_message(
    source: &Path,
    session: &str,
    id: &str,
    created: i64,
    tokens: Option<Value>,
) -> TestResult {
    let path = source.join(format!("storage/message/{session}/{id}.json"));
    std::fs::create_dir_all(path.parent().ok_or("parent")?)?;
    let mut message = json!({"role": "assistant", "time": {"created": created}});
    if let Some(tokens) = tokens {
        message["tokens"] = tokens;
    }
    std::fs::write(path, serde_json::to_vec(&message)?)?;
    Ok(())
}

fn write_json_part(source: &Path, message: &str, id: &str, payload: &Value) -> TestResult {
    let path = source.join(format!("storage/part/{message}/{id}.json"));
    std::fs::create_dir_all(path.parent().ok_or("parent")?)?;
    std::fs::write(path, serde_json::to_vec(payload)?)?;
    Ok(())
}

fn find<'a>(
    records: &'a [SourceReportedObservation],
    message: &str,
) -> &'a SourceReportedObservation {
    records
        .iter()
        .find(|record| record.message_id == message)
        .unwrap_or_else(|| panic!("record {message} missing"))
}

/// (input, output, reasoning, cache_read, cache_write, total) values of a record.
fn values(record: &SourceReportedObservation) -> [Option<u64>; 6] {
    [
        record.input.value,
        record.output.value,
        record.reasoning.value,
        record.cache_read.value,
        record.cache_write.value,
        record.total.value,
    ]
}

fn history(data: &Path) -> TestResult<Connection> {
    Ok(Connection::open_with_flags(
        data.join("history.sqlite"),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?)
}

#[test]
fn partial_counters_survive_without_an_aggregate_in_every_layout() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let c = open_fixture(&source.join("opencode.db"))?;
    let two = counts(Some(10), Some(20), None, None, None, None);
    put_message(
        &c,
        "legacy-partial",
        "s",
        T0,
        &json!({"role": "assistant", "tokens": two}),
    )?;
    put_v2(
        &c,
        "v2-partial",
        "s2",
        "assistant",
        1,
        T0,
        &json!({"tokens": two}),
    )?;
    let only_zero = counts(Some(0), None, None, None, None, None);
    put_message(
        &c,
        "legacy-zero",
        "s",
        T0,
        &json!({"role": "assistant", "tokens": only_zero}),
    )?;
    put_message(&c, "legacy-group", "s", T0, &json!({"role": "assistant"}))?;
    let first = counts(Some(1), Some(2), None, None, None, None);
    let second = counts(Some(3), Some(4), None, None, None, None);
    put_part(&c, "p1", "legacy-group", "s", &step_finish(first))?;
    put_part(&c, "p2", "legacy-group", "s", &step_finish(second))?;
    write_json_message(&source, "sj", "json-partial", T0, Some(two.clone()))?;
    write_json_message(&source, "sj", "json-group", T0, None)?;
    let json_first = counts(Some(5), None, None, None, None, None);
    let json_second = counts(Some(6), Some(7), None, None, None, None);
    write_json_part(&source, "json-group", "p1", &step_finish(json_first))?;
    write_json_part(&source, "json-group", "p2", &step_finish(json_second))?;
    let mut engine = open_engine(&source, &data, &home)?;
    let report = engine.pass(consented(), 1);
    assert_eq!(report.outcome, PassOutcome::Consistent, "{report:?}");
    assert_eq!(report.records_committed, 6);
    let records = engine.observations()?;

    for id in ["legacy-partial", "v2-partial", "json-partial"] {
        let record = find(&records, id);
        assert_eq!(
            values(record),
            [Some(10), Some(20), None, None, None, None],
            "{id}"
        );
        assert_eq!(record.input.provenance, Some(Provenance::Reported), "{id}");
        assert_eq!(
            record.reasoning.status,
            ObservationStatus::Unavailable,
            "{id}"
        );
        assert_eq!(record.reasoning.provenance, None, "{id}");
        assert_eq!(record.total.status, ObservationStatus::Unavailable, "{id}");
        assert_eq!(record.total.provenance, None, "{id}");
    }
    let zero = find(&records, "legacy-zero");
    assert_eq!(values(zero), [Some(0), None, None, None, None, None]);
    assert_eq!(zero.input.status, ObservationStatus::Current);
    assert_eq!(zero.input.provenance, Some(Provenance::Reported));
    // Parts: a component present in every part sums; one missing from any part stays unknown.
    let legacy_group = find(&records, "legacy-group");
    assert_eq!(
        values(legacy_group),
        [Some(4), Some(6), None, None, None, None]
    );
    assert_eq!(legacy_group.selected_part_ids, ["p1", "p2"]);
    let json_group = find(&records, "json-group");
    assert_eq!(values(json_group), [Some(11), None, None, None, None, None]);
    assert_eq!(json_group.selected_part_ids, ["p1", "p2"]);

    let projection = engine.snapshot(&report)?.projection;
    assert_eq!(projection.records, 6);
    assert_eq!(projection.input.value, Some(10 + 10 + 4 + 10 + 11));
    assert_eq!(projection.input.status, ObservationStatus::Current);
    assert_eq!(projection.output.status, ObservationStatus::Partial);
    assert_eq!(projection.reasoning.value, None);
    assert_eq!(projection.reasoning.status, ObservationStatus::Unavailable);
    assert_eq!(projection.total.value, None);
    assert_eq!(projection.total.status, ObservationStatus::Unavailable);
    Ok(())
}

#[test]
fn part_totals_resolve_explicit_or_permitted_derived_before_aggregation() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let c = open_fixture(&source.join("opencode.db"))?;
    let complete = |seed: u64| {
        counts(
            Some(seed),
            Some(seed),
            Some(seed),
            Some(seed),
            Some(seed),
            None,
        )
    };
    // Part 1 reports total 40; part 2 has no total but all five components (derived 7).
    put_message(&c, "mixed", "s", T0, &json!({"role": "assistant"}))?;
    let reported = counts(Some(1), Some(2), Some(3), Some(4), Some(5), Some(40));
    put_part(&c, "p1", "mixed", "s", &step_finish(reported))?;
    let derivable = counts(Some(1), Some(1), Some(1), Some(2), Some(2), None);
    put_part(&c, "p2", "mixed", "s", &step_finish(derivable))?;
    // Every part derives: the total is the sum of derived part totals.
    put_message(&c, "derived", "s", T0, &json!({"role": "assistant"}))?;
    put_part(&c, "p1", "derived", "s", &step_finish(complete(1)))?;
    put_part(&c, "p2", "derived", "s", &step_finish(complete(2)))?;
    // A part with neither explicit nor derivable total leaves the group without a total.
    put_message(&c, "unresolved", "s", T0, &json!({"role": "assistant"}))?;
    let full = counts(Some(1), Some(1), Some(1), Some(1), Some(1), Some(9));
    put_part(&c, "p1", "unresolved", "s", &step_finish(full))?;
    let short = counts(Some(2), Some(2), Some(2), Some(2), None, None);
    put_part(&c, "p2", "unresolved", "s", &step_finish(short))?;
    let mut engine = open_engine(&source, &data, &home)?;
    assert_eq!(engine.pass(consented(), 1).outcome, PassOutcome::Consistent);
    let records = engine.observations()?;

    let mixed = find(&records, "mixed");
    assert_eq!(mixed.total.value, Some(47), "explicit 40 + derived 7");
    // One derived part makes the group total derived and discloses the pinned convention; the
    // explicit 40 disagrees with its own components, which stays visible as a mismatch.
    assert_eq!(mixed.total.provenance, Some(Provenance::Derived));
    assert_eq!(
        mixed.source_convention.as_deref(),
        Some("codexbar-3239175f-disjoint")
    );
    assert!(mixed.total_mismatch, "47 against components summing to 22");
    assert_eq!(mixed.input.value, Some(2));
    let derived = find(&records, "derived");
    assert_eq!(derived.total.value, Some(5 + 10));
    assert_eq!(derived.total.provenance, Some(Provenance::Derived));
    assert_eq!(
        derived.source_convention.as_deref(),
        Some("codexbar-3239175f-disjoint")
    );
    let unresolved = find(&records, "unresolved");
    assert_eq!(unresolved.total.value, None);
    assert_eq!(unresolved.total.status, ObservationStatus::Unavailable);
    assert_eq!(unresolved.input.value, Some(3));
    assert_eq!(unresolved.cache_write.value, None);
    Ok(())
}

#[test]
fn parent_envelope_is_validated_independently_of_parent_usage() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let c = open_fixture(&source.join("opencode.db"))?;
    let part = step_finish(counts(Some(1), Some(2), Some(0), Some(0), Some(0), Some(3)));
    // A user message never contributes, whatever parts hang off it.
    put_message(&c, "user-parent", "s", T0, &json!({"role": "user"}))?;
    put_part(&c, "p1", "user-parent", "s", &part)?;
    // An assistant parent without usage still needs a valid time.
    put_message(&c, "bad-time", "s", -5, &json!({"role": "assistant"}))?;
    put_part(&c, "p1", "bad-time", "s", &part)?;
    put_message(&c, "no-time", "s", T0, &json!({"role": "assistant"}))?;
    c.execute(
        "UPDATE message SET time_created = NULL WHERE id = 'no-time'",
        [],
    )?;
    put_part(&c, "p1", "no-time", "s", &part)?;
    // A parent that is not JSON is rejected even though its parts are fine.
    c.execute(
        "INSERT INTO message(id, session_id, time_created, data) VALUES ('garbage', 's', ?1, ?2)",
        rusqlite::params![T0, b"{".to_vec()],
    )?;
    put_part(&c, "p1", "garbage", "s", &part)?;
    // The valid control: a usage-free assistant parent with a part is a group.
    put_message(&c, "valid", "s", T0, &json!({"role": "assistant"}))?;
    put_part(&c, "p1", "valid", "s", &part)?;
    let mut engine = open_engine(&source, &data, &home)?;
    let report = engine.pass(consented(), 1);
    assert_eq!(report.outcome, PassOutcome::Partial, "{report:?}");
    assert_eq!(report.failure, Some(FailureCode::InvalidRecord));
    assert_eq!(report.counters.rejected_records, 3);
    let records = engine.observations()?;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].message_id, "valid");
    assert_eq!(records[0].total.value, Some(3));
    Ok(())
}

const MESSAGE_DDL: &str = "CREATE TABLE message(id TEXT NOT NULL, session_id TEXT NOT NULL, \
    time_created INTEGER, data BLOB NOT NULL, PRIMARY KEY(id, session_id));";
const PART_DDL: &str = "CREATE TABLE part(id TEXT NOT NULL, message_id TEXT NOT NULL, \
    session_id TEXT NOT NULL, data BLOB NOT NULL, PRIMARY KEY(id, message_id));";
const V2_MESSAGE_DDL: &str = "CREATE TABLE session_message(id TEXT NOT NULL, session_id TEXT NOT NULL, \
    type TEXT NOT NULL, seq INTEGER NOT NULL, time_created INTEGER, data BLOB NOT NULL, \
    PRIMARY KEY(id, session_id));";

#[test]
fn incomplete_or_malformed_schemas_are_unsupported_not_empty_success() -> TestResult {
    let _guard = vfs_test_guard();
    let session = "CREATE TABLE session(id TEXT PRIMARY KEY);";
    let session_v2 = "CREATE TABLE session_v2(id TEXT PRIMARY KEY);";
    let cases: Vec<(&str, String)> = vec![
        ("message-only", MESSAGE_DDL.to_owned()),
        ("no-session", format!("{MESSAGE_DDL}{PART_DDL}")),
        ("no-part", format!("{session}{MESSAGE_DDL}")),
        (
            "message-column",
            format!(
                "{session}CREATE TABLE message(id TEXT NOT NULL, session_id TEXT NOT NULL, \
                 data BLOB NOT NULL, PRIMARY KEY(id, session_id));{PART_DDL}"
            ),
        ),
        (
            "v2-no-seq",
            format!(
                "{session_v2}CREATE TABLE session_message(id TEXT NOT NULL, session_id TEXT NOT NULL, \
                 type TEXT NOT NULL, time_created INTEGER, data BLOB NOT NULL, PRIMARY KEY(id, session_id));"
            ),
        ),
        ("v2-no-session", V2_MESSAGE_DDL.to_owned()),
        (
            "without-rowid",
            format!(
                "{session}CREATE TABLE message(id TEXT NOT NULL, session_id TEXT NOT NULL, \
                 time_created INTEGER, data BLOB NOT NULL, PRIMARY KEY(id, session_id)) WITHOUT ROWID;{PART_DDL}"
            ),
        ),
        ("unrelated", "CREATE TABLE notes(id TEXT);".to_owned()),
        (
            "legacy-plus-incomplete-v2",
            format!("{session}{MESSAGE_DDL}{PART_DDL}{session_v2}"),
        ),
    ];
    for (name, ddl) in cases {
        let directory = tempdir()?;
        let (source, data, home) = source_roots(directory.path())?;
        Connection::open(source.join("opencode.db"))?.execute_batch(&ddl)?;
        let mut engine = open_engine(&source, &data, &home)?;
        let report = engine.pass(consented(), 1);
        assert_eq!(
            report.outcome,
            PassOutcome::Unavailable,
            "{name}: {report:?}"
        );
        assert_eq!(
            report.failure,
            Some(FailureCode::UnsupportedSchema),
            "{name}"
        );
        assert_eq!(report.records_committed, 0, "{name}");
        assert!(engine.observations()?.is_empty(), "{name}");
    }
    // Controls: each complete layout alone is supported.
    for layout in ["legacy", "v2"] {
        let directory = tempdir()?;
        let (source, data, home) = source_roots(directory.path())?;
        let c = open_fixture(&source.join("opencode.db"))?;
        let one = counts(Some(1), None, None, None, None, None);
        if layout == "legacy" {
            put_message(
                &c,
                "m",
                "s",
                T0,
                &json!({"role": "assistant", "tokens": one}),
            )?;
            c.execute_batch("DROP TABLE session_message; DROP TABLE session_v2;")?;
        } else {
            put_v2(&c, "m", "s", "assistant", 1, T0, &json!({"tokens": one}))?;
            c.execute_batch("DROP TABLE part; DROP TABLE message; DROP TABLE session;")?;
        }
        drop(c);
        let mut engine = open_engine(&source, &data, &home)?;
        let report = engine.pass(consented(), 1);
        assert_eq!(
            report.outcome,
            PassOutcome::Consistent,
            "{layout}: {report:?}"
        );
        assert_eq!(report.records_committed, 1, "{layout}");
    }
    Ok(())
}

#[test]
fn timestamps_are_pinned_epoch_milliseconds_inside_the_calendar() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let c = open_fixture(&source.join("opencode.db"))?;
    let usage = json!({"role": "assistant", "tokens": counts(Some(1), Some(1), Some(1), Some(1), Some(1), None)});
    // The last millisecond the calendar can represent, found independently of the product.
    let latest = (0..2_000)
        .map(|back| jiff::Timestamp::MAX.as_millisecond() - back)
        .find(|ms| jiff::Timestamp::from_millisecond(*ms).is_ok())
        .ok_or("calendar maximum")?;
    assert!(jiff::Timestamp::from_millisecond(latest + 1).is_err());
    let accepted = [
        ("epoch", 0_i64),
        ("year-2100", 4_102_444_800_000),
        ("latest", latest),
        ("seconds-like", 1_700_000_000),
    ];
    for (id, time) in accepted {
        put_message(&c, id, "s", time, &usage)?;
    }
    for (id, time) in [
        ("negative", -1_i64),
        ("after-calendar", latest + 1),
        ("i64-max", i64::MAX),
    ] {
        put_message(&c, id, "s", time, &usage)?;
    }
    c.execute(
        "INSERT INTO message(id, session_id, time_created, data) VALUES ('real-time', 's', 1.5, ?1)",
        [serde_json::to_vec(&usage)?],
    )?;
    c.execute(
        "INSERT INTO message(id, session_id, time_created, data) VALUES ('text-time', 's', 'soon', ?1)",
        [serde_json::to_vec(&usage)?],
    )?;
    let one = counts(Some(1), None, None, None, None, None);
    write_json_message(&source, "sj", "json-seconds", 1_700_000_000, Some(one))?;
    let mut engine = open_engine(&source, &data, &home)?;
    let report = engine.pass(consented(), 1);
    assert_eq!(report.outcome, PassOutcome::Partial, "{report:?}");
    assert_eq!(
        report.counters.rejected_records,
        5,
        "{report:?} accepted={:?}",
        engine
            .observations()?
            .iter()
            .map(|r| r.message_id.clone())
            .collect::<Vec<_>>()
    );
    let records = engine.observations()?;
    let ids = records
        .iter()
        .map(|record| record.message_id.as_str())
        .collect::<Vec<_>>();
    for accepted in [
        "epoch",
        "year-2100",
        "latest",
        "seconds-like",
        "json-seconds",
    ] {
        assert!(ids.contains(&accepted), "{accepted} accepted: {ids:?}");
    }
    assert_eq!(
        find(&records, "seconds-like").occurred_at_ms,
        1_700_000_000,
        "no seconds rescaling"
    );
    assert_eq!(
        find(&records, "json-seconds").occurred_at_ms,
        1_700_000_000,
        "no seconds rescaling"
    );
    assert_eq!(find(&records, "latest").occurred_at_ms, latest);
    for rejected in [
        "negative",
        "after-calendar",
        "i64-max",
        "real-time",
        "text-time",
    ] {
        assert!(!ids.contains(&rejected), "{rejected} rejected: {ids:?}");
    }
    assert_eq!(records.len(), 5);
    Ok(())
}

/// Rows the production schema admission emits for a database, derived independently from the
/// file: the encoding pragma, then per layout table one existence row plus one row per column.
fn admission_rows(database: &Path) -> TestResult<u64> {
    let connection = Connection::open_with_flags(
        format!("file:{}?immutable=1", database.display()),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )?;
    let mut rows = 1_u64;
    for table in [
        "session",
        "message",
        "part",
        "session_v2",
        "session_message",
    ] {
        let columns: i64 = connection.query_row(
            "SELECT COUNT(*) FROM pragma_table_info(?1)",
            [table],
            |row| row.get(0),
        )?;
        rows += 1 + u64::try_from(columns)?;
    }
    Ok(rows)
}

fn emoji_record(emoji: usize) -> TestResult<String> {
    Ok(serde_json::to_string(&json!({
        "role": "assistant",
        "tokens": counts(Some(1), Some(1), Some(1), Some(1), Some(1), None),
        "content": "\u{1F600}".repeat(emoji)
    }))?)
}

#[test]
fn multibyte_text_payloads_are_accounted_in_bytes_before_materialization() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let c = open_fixture(&source.join("opencode.db"))?;
    // 25_000 four-byte characters per record, stored as TEXT: SQLite's character-counting
    // `length()` would report about a quarter of the real byte size.
    let valid = emoji_record(25_000)?;
    let valid_bytes = valid.len() as u64;
    assert!(
        valid.chars().count() < valid.len() / 3,
        "chars {} bytes {}",
        valid.chars().count(),
        valid.len()
    );
    let tx = c.unchecked_transaction()?;
    for index in 0..700 {
        tx.execute(
            "INSERT INTO message(id, session_id, time_created, data) VALUES (?1, 's', ?2, ?3)",
            rusqlite::params![format!("valid-{index:04}"), T0, valid],
        )?;
    }
    // Characters fit under 256 KiB but the bytes do not.
    let oversized = emoji_record(65_537)?;
    assert!(oversized.chars().count() < 256 * 1024 && oversized.len() > 256 * 1024);
    tx.execute(
        "INSERT INTO message(id, session_id, time_created, data) VALUES ('zz-oversized', 's', ?1, ?2)",
        rusqlite::params![T0, oversized],
    )?;
    // The exact cap, and cap + 1 byte, as BLOBs.
    let shell = r#"{"role":"assistant","tokens":{"input":1},"content":""}"#;
    let filler = "x".repeat(256 * 1024 - shell.len());
    let at_cap = shell.replace("\"content\":\"\"", &format!("\"content\":\"{filler}\""));
    assert_eq!(at_cap.len(), 256 * 1024);
    tx.execute(
        "INSERT INTO message(id, session_id, time_created, data) VALUES ('zz-at-cap', 's', ?1, ?2)",
        rusqlite::params![T0, at_cap.as_bytes()],
    )?;
    let over_cap = format!("{at_cap} ");
    tx.execute(
        "INSERT INTO message(id, session_id, time_created, data) VALUES ('zz-over-cap', 's', ?1, ?2)",
        rusqlite::params![T0, over_cap.as_bytes()],
    )?;
    tx.commit()?;
    drop(c);
    let mut engine = open_engine(&source, &data, &home)?;
    let first = engine.pass(consented(), 1);
    assert_eq!(first.outcome, PassOutcome::CatchingUp, "{first:?}");
    let fit = (64 * 1024 * 1024) / valid_bytes;
    assert_eq!(
        u64::from(first.counters.rows_read),
        fit + 1 + admission_rows(&source.join("opencode.db"))?,
        "rows read until the byte budget, plus the emitted row that did not fit"
    );
    assert_eq!(
        first.counters.bytes_read,
        fit * valid_bytes,
        "exact byte accounting"
    );
    assert_eq!(
        engine.snapshot(&first)?.projection.records,
        fit,
        "finished groups publish"
    );
    let last = engine.pass(consented(), 2);
    assert_eq!(last.outcome, PassOutcome::Partial, "{last:?}");
    assert_eq!(last.failure, Some(FailureCode::RecordTooLarge));
    assert_eq!(
        last.counters.rejected_records, 2,
        "cap + 1 and oversized rejected"
    );
    assert_eq!(
        u64::from(last.counters.rows_read),
        700 - fit + 3 + admission_rows(&source.join("opencode.db"))?,
        "remaining valid rows and the three boundary rows"
    );
    assert_eq!(
        last.counters.bytes_read,
        (700 - fit) * valid_bytes + 256 * 1024,
        "rejected payloads are never counted or fetched"
    );
    let records = engine.snapshot(&last)?.projection.records;
    assert_eq!(records, 701, "700 valid + the exact-cap record");
    Ok(())
}

#[test]
fn oversized_identity_and_type_columns_are_never_materialized_or_persisted() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let c = open_fixture(&source.join("opencode.db"))?;
    let usage =
        json!({"role": "assistant", "tokens": counts(Some(1), None, None, None, None, None)});
    let (long_session, long_message) = ("S".repeat(300), "M".repeat(300));
    let (long_part, long_type) = ("P".repeat(300), "T".repeat(4_096));
    put_message(&c, "ok", "s", T0, &usage)?;
    put_message(&c, "long-session", &long_session, T0, &usage)?;
    put_message(&c, &long_message, "s", T0, &usage)?;
    put_message(&c, "with-long-part", "s", T0, &json!({"role": "assistant"}))?;
    let nine = counts(Some(9), None, None, None, None, None);
    put_part(&c, &long_part, "with-long-part", "s", &step_finish(nine))?;
    c.execute(
        "INSERT INTO message(id, session_id, time_created, data) VALUES (x'6161', 's', ?1, ?2)",
        rusqlite::params![T0, serde_json::to_vec(&usage)?],
    )?;
    c.execute(
        "INSERT INTO message(id, session_id, time_created, data) VALUES ('integer-data', 's', ?1, 42)",
        [T0],
    )?;
    let one = counts(Some(1), None, None, None, None, None);
    put_v2(
        &c,
        "v2-long-type",
        "s2",
        &long_type,
        1,
        T0,
        &json!({"tokens": one}),
    )?;
    let two = counts(Some(2), None, None, None, None, None);
    put_v2(
        &c,
        "v2-ok",
        "s2",
        "assistant",
        2,
        T0,
        &json!({"tokens": two}),
    )?;
    drop(c);
    let mut engine = open_engine(&source, &data, &home)?;
    let reports = run_until_consistent(&mut engine, 1, 4);
    let last = reports.last().ok_or("pass")?;
    assert_eq!(last.outcome, PassOutcome::Partial, "{last:?}");
    assert_eq!(last.failure, Some(FailureCode::InvalidRecord));
    let records = engine.observations()?;
    let ids = records
        .iter()
        .map(|record| record.message_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(ids.len(), 2, "{ids:?}");
    assert!(ids.contains(&"ok") && ids.contains(&"v2-ok"));
    // Nothing attacker-sized reached the application store, cursors included.
    let h = history(&data)?;
    let mut text = String::new();
    for table in [
        "opencode_progress",
        "opencode_candidate_spool",
        "reported_groups",
        "usage_events",
        "acquisition_failures",
    ] {
        let mut statement = h.prepare(&format!("SELECT * FROM {table}"))?;
        let columns = statement.column_count();
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            for index in 0..columns {
                if let Ok(value) = row.get::<_, String>(index) {
                    text.push_str(&value);
                }
            }
        }
    }
    for needle in [&long_session, &long_message, &long_part, &long_type] {
        assert!(!text.contains(needle.as_str()), "oversized value persisted");
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Drain, paging, numeric cap, query plan and work bounds
// ---------------------------------------------------------------------------------------------

#[test]
fn legacy_and_v2_sources_drain_across_the_five_thousand_row_budget() -> TestResult {
    let _guard = vfs_test_guard();
    for (rows, with_parts) in [
        (5_000_u32, false),
        (5_001, false),
        (5_001, true),
        (4_999, true),
    ] {
        let directory = tempdir()?;
        let (source, data, home) = source_roots(directory.path())?;
        let c = open_fixture(&source.join("opencode.db"))?;
        let tx = c.unchecked_transaction()?;
        let payload = serde_json::to_vec(&json!({
            "role": "assistant",
            "tokens": counts(Some(1), Some(2), Some(0), Some(0), Some(0), None)
        }))?;
        let part = serde_json::to_vec(&step_finish(counts(
            Some(10),
            Some(10),
            Some(0),
            Some(0),
            Some(0),
            None,
        )))?;
        for index in 0..rows {
            tx.execute(
                "INSERT INTO message(id, session_id, time_created, data) VALUES (?1, 's', ?2, ?3)",
                rusqlite::params![format!("m-{index:05}"), T0 + i64::from(index), payload],
            )?;
            if with_parts && index % 1_000 == 0 {
                tx.execute(
                    "INSERT INTO part(id, message_id, session_id, time_created, data) VALUES ('p1', ?1, 's', 1, ?2)",
                    rusqlite::params![format!("m-{index:05}"), part],
                )?;
            }
        }
        tx.commit()?;
        drop(c);
        let mut engine = open_engine(&source, &data, &home)?;
        let groups = if with_parts { rows.div_ceil(1_000) } else { 0 };
        let mut passes = 0;
        let mut restarts = 0;
        let mut last = engine.pass(consented(), 1);
        loop {
            // After a reopen, one pass reconstructs partly read directories and reads nothing.
            let restart = last.outcome == PassOutcome::Partial
                && last.failure == Some(FailureCode::LimitExceeded)
                && last.counters.entries == 0
                && last.counters.rows_read == 0;
            if restart {
                restarts += 1;
                assert_eq!(restarts, 1, "one restart, then bounded passes drain");
                last = engine.pass(consented(), 100 + passes);
                continue;
            }
            passes += 1;
            assert!(last.counters.rows_read <= 5_000);
            if last.outcome == PassOutcome::Consistent {
                break;
            }
            assert_eq!(
                last.outcome,
                PassOutcome::CatchingUp,
                "{rows}/{with_parts}: {last:?}"
            );
            assert!(
                last.records_committed > 0,
                "every capped pass publishes the groups it finished"
            );
            assert!(passes < 6, "source must drain");
            if passes == 1 {
                // A restart between passes resumes from the persisted cursor.
                drop(engine);
                engine = open_engine(&source, &data, &home)?;
            }
            last = engine.pass(consented(), 1 + passes);
        }
        let projection = engine.snapshot(&last)?.projection;
        assert_eq!(projection.records, u64::from(rows), "{rows}/{with_parts}");
        // Parts replace their parent: those records carry 10/10 instead of 1/2.
        let expected_input = u64::from(rows - groups) + u64::from(groups) * 10;
        assert_eq!(
            projection.input.value,
            Some(expected_input),
            "{rows}/{with_parts}"
        );
        let minimum = if rows + groups >= 5_000 { 2 } else { 1 };
        assert!(passes >= minimum, "{rows}/{with_parts}: {passes} passes");
    }
    Ok(())
}

#[test]
fn raw_history_is_paged_and_numeric_projection_is_bounded() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let c = open_fixture(&source.join("opencode.db"))?;
    let tx = c.unchecked_transaction()?;
    for index in 0..1_050_i64 {
        let payload = if index % 2 == 0 {
            json!({"role": "assistant", "tokens": counts(Some(2), Some(0), None, None, None, None)})
        } else {
            json!({"role": "assistant", "tokens": counts(Some(3), None, None, None, None, Some(7))})
        };
        tx.execute(
            "INSERT INTO message(id, session_id, time_created, data) VALUES (?1, 's', ?2, ?3)",
            rusqlite::params![
                format!("m-{index:05}"),
                T0 + index,
                serde_json::to_vec(&payload)?
            ],
        )?;
    }
    tx.commit()?;
    drop(c);
    let mut engine = open_engine(&source, &data, &home)?;
    let report = engine.pass(consented(), 1);
    assert_eq!(report.outcome, PassOutcome::Consistent);
    assert_eq!(
        engine.observations().err(),
        Some(quotern_core::store::StoreError::LimitExceeded),
        "an unbounded raw read is refused, never truncated"
    );
    let mut cursor = None;
    let mut seen = Vec::new();
    loop {
        let page = engine.observations_page(cursor.as_ref(), 400)?;
        assert!(page.observations.len() <= 400);
        seen.extend(
            page.observations
                .iter()
                .map(|record| record.message_id.clone()),
        );
        cursor = page.next;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(seen.len(), 1_050);
    assert!(seen.windows(2).all(|pair| pair[0] < pair[1]));
    let snapshot = engine.snapshot(&report)?;
    let projection = &snapshot.projection;
    assert_eq!(projection.records, 1_050);
    assert_eq!(projection.input.value, Some(525 * 2 + 525 * 3));
    assert_eq!(projection.input.status, ObservationStatus::Current);
    assert_eq!(projection.output.value, Some(0), "explicit zero is a value");
    assert_eq!(
        projection.output.status,
        ObservationStatus::Partial,
        "half omit output"
    );
    assert_eq!(projection.reasoning.value, None);
    assert_eq!(projection.reasoning.status, ObservationStatus::Unavailable);
    assert_eq!(
        projection.total.value,
        Some(525 * 7),
        "only reported totals; the rest stay unknown"
    );
    assert_eq!(projection.total.status, ObservationStatus::Partial);
    assert_eq!(projection.total.provenance, Some(Provenance::Reported));
    assert!(
        serde_json::to_vec(&snapshot)?.len() < 4_096,
        "size does not grow with history"
    );
    Ok(())
}

#[test]
fn summed_part_components_are_revalidated_against_the_numeric_cap() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let c = open_fixture(&source.join("opencode.db"))?;
    let cap = 1_000_000_000_000_u64;
    let part = |input: u64, total: u64| {
        step_finish(counts(
            Some(input),
            Some(0),
            Some(0),
            Some(0),
            Some(0),
            Some(total),
        ))
    };
    // Every part is within the cap and the explicit totals are tiny, but the input sum is not.
    put_message(&c, "over", "s", T0, &json!({"role": "assistant"}))?;
    put_part(&c, "p1", "over", "s", &part(cap / 2 + 1, 1))?;
    put_part(&c, "p2", "over", "s", &part(cap / 2, 1))?;
    put_message(&c, "exact", "s", T0, &json!({"role": "assistant"}))?;
    put_part(&c, "p1", "exact", "s", &part(cap / 2, 1))?;
    put_part(&c, "p2", "exact", "s", &part(cap / 2, 1))?;
    let mut engine = open_engine(&source, &data, &home)?;
    let report = engine.pass(consented(), 1);
    assert_eq!(report.outcome, PassOutcome::Partial, "{report:?}");
    assert_eq!(report.counters.rejected_records, 1);
    let records = engine.observations()?;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].message_id, "exact");
    assert_eq!(records[0].input.value, Some(cap));

    // The store enforces the same ceiling independently of the adapter.
    let root = directory.path().join("root");
    std::fs::create_dir_all(&root)?;
    let mut store = quotern_core::store::Store::open(&directory.path().join("store-only"))
        .map_err(|error| format!("store open: {error:?}"))?;
    let registration = store
        .register_source(&root, quotern_core::domain::SourceKind::Custom, (1, 1))
        .map_err(|error| format!("register: {error:?}"))?;
    let candidate = quotern_core::domain::RecordCandidate {
        session_id: "s".to_owned(),
        message_id: "direct".to_owned(),
        occurred_at_ms: T0,
        components: quotern_core::domain::TokenComponents {
            input: Some(cap + 1),
            ..Default::default()
        },
        total: Some(1),
        total_provenance: Some(quotern_core::domain::Provenance::Reported),
        source_convention: None,
        acquisition_consistency:
            quotern_core::domain::AcquisitionConsistency::SqliteReadTransaction,
        selected_part_ids: Vec::new(),
        pending_partial: false,
        canonical_path: root.join("opencode.db"),
        format_rank: 0,
        fingerprint: 1,
    };
    let result = store.commit_generation(quotern_core::store::CommitRequest {
        source_id: &registration.source_id,
        root: &root,
        generation: registration.generation,
        batch: quotern_core::store::StageBatch {
            candidates: std::slice::from_ref(&candidate),
            ..Default::default()
        },
        outcome: PassOutcome::Consistent,
        failure: None,
        rejection: None,
        terminal: true,
        counters: Default::default(),
        now_ms: 1,
    });
    assert_eq!(
        result.err(),
        Some(quotern_core::store::StoreError::CountOutOfRange)
    );
    assert!(store.observations(&registration.source_id)?.is_empty());
    Ok(())
}

/// Plan text of each row of `EXPLAIN QUERY PLAN`.
fn plan(
    connection: &Connection,
    sql: &str,
    parameters: &[&dyn rusqlite::ToSql],
) -> TestResult<Vec<String>> {
    let mut statement = connection.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?;
    let rows = statement.query_map(parameters, |row| row.get::<_, String>(3))?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

fn vm_steps(
    connection: &Connection,
    sql: &str,
    parameters: &[&dyn rusqlite::ToSql],
) -> TestResult<i32> {
    let mut statement = connection.prepare(sql)?;
    let mut rows = statement.query(parameters)?;
    while rows.next()?.is_some() {}
    drop(rows);
    Ok(statement.get_status(rusqlite::StatementStatus::VmStep))
}

#[test]
fn source_queries_use_index_order_and_bounded_work() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let build = |name: &str, messages: i64, indexed: bool| -> TestResult<Connection> {
        let path = directory.path().join(name);
        let c = open_fixture(&path)?;
        if !indexed {
            c.execute_batch("DROP INDEX part_message_id_id_idx;")?;
        }
        let tx = c.unchecked_transaction()?;
        let payload = serde_json::to_vec(
            &json!({"role": "assistant", "tokens": counts(Some(1), None, None, None, None, None), "content": "x".repeat(2_000)}),
        )?;
        for index in 0..messages {
            tx.execute(
                "INSERT INTO message(id, session_id, time_created, data) VALUES (?1, 's', 1, ?2)",
                rusqlite::params![format!("m-{index:06}"), payload],
            )?;
            tx.execute(
                "INSERT INTO part(id, message_id, session_id, time_created, data) VALUES ('p1', ?1, 's', 1, ?2)",
                rusqlite::params![format!("m-{index:06}"), payload],
            )?;
        }
        tx.commit()?;
        Ok(c)
    };
    let message_sql = quotern_core::adapters::opencode::message_query(
        false,
        quotern_core::adapters::opencode::Lower::After,
    );
    let message_params: [&dyn rusqlite::ToSql; 6] = [
        &256_i64,
        &262_144_i64,
        &10_i64,
        &32_i64,
        &67_108_864_i64,
        &i64::MIN,
    ];
    let part_params: [&dyn rusqlite::ToSql; 4] = [&"m-000001", &"s", &256_i64, &257_i64];
    let indexed = build("indexed.db", 2_000, true)?;
    let small = build("small.db", 200, true)?;

    let message_plan = plan(&indexed, &message_sql, &message_params)?.join(" | ");
    assert!(
        message_plan.contains("USING INTEGER PRIMARY KEY"),
        "{message_plan}"
    );
    assert!(!message_plan.contains("TEMP B-TREE"), "{message_plan}");
    let part_plan = plan(
        &indexed,
        quotern_core::adapters::opencode::PART_LIST_SQL,
        &part_params,
    )?
    .join(" | ");
    assert!(part_plan.contains("part_message_id_id_idx"), "{part_plan}");
    assert!(!part_plan.contains("TEMP B-TREE"), "{part_plan}");
    let payload_plan = plan(
        &indexed,
        quotern_core::adapters::opencode::PART_PAYLOAD_SQL,
        &[&"p1", &"m-000001", &262_144_i64],
    )?
    .join(" | ");
    assert!(!payload_plan.contains("TEMP B-TREE"), "{payload_plan}");
    // Control: without the index the plan scans, which the detector reports.
    let unindexed = build("unindexed.db", 50, false)?;
    let scan_plan = plan(
        &unindexed,
        quotern_core::adapters::opencode::PART_LIST_SQL,
        &part_params,
    )?
    .join(" | ");
    assert!(
        scan_plan.contains("SCAN part") || scan_plan.contains("TEMP B-TREE"),
        "{scan_plan}"
    );

    // Work for one page is independent of table size: no hidden scan or payload-sized sort.
    let big_steps = vm_steps(&indexed, &message_sql, &message_params)?;
    let small_steps = vm_steps(&small, &message_sql, &message_params)?;
    assert!(
        big_steps <= small_steps + small_steps / 4 + 50,
        "{big_steps} vs {small_steps}"
    );
    let part_big = vm_steps(
        &indexed,
        quotern_core::adapters::opencode::PART_LIST_SQL,
        &part_params,
    )?;
    let part_small = vm_steps(
        &small,
        quotern_core::adapters::opencode::PART_LIST_SQL,
        &part_params,
    )?;
    assert!(
        part_big <= part_small + part_small / 4 + 50,
        "{part_big} vs {part_small}"
    );
    Ok(())
}

#[test]
fn unindexed_source_work_stops_at_the_work_limit_and_keeps_whole_group_progress() -> TestResult {
    /// Restores the default progress allowance even when an assertion fails.
    struct Ticks;
    impl Drop for Ticks {
        fn drop(&mut self) {
            quotern_core::adapters::opencode::set_progress_ticks(None);
        }
    }
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let c = open_fixture(&source.join("opencode.db"))?;
    c.execute_batch("DROP INDEX part_message_id_id_idx;")?;
    let tx = c.unchecked_transaction()?;
    let payload = serde_json::to_vec(
        &json!({"role": "assistant", "tokens": counts(Some(1), None, None, None, None, None)}),
    )?;
    for index in 0..3_000_i64 {
        tx.execute(
            "INSERT INTO message(id, session_id, time_created, data) VALUES (?1, 's', 1, ?2)",
            rusqlite::params![format!("m-{index:05}"), payload],
        )?;
    }
    // A part table without an index: every group's part lookup scans all of it.
    tx.execute_batch(
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 20000) \
         INSERT INTO part(id, message_id, session_id, time_created, data) \
         SELECT 'p' || i, 'other-' || i, 's', 1, x'7b7d' FROM n;",
    )?;
    tx.commit()?;
    drop(c);
    let mut engine = open_engine(&source, &data, &home)?;
    // The work allowance is counted in SQLite progress callbacks (virtual-machine work), not time.
    quotern_core::adapters::opencode::set_progress_ticks(Some(450));
    let _ticks = Ticks;
    let published_ids = |data: &Path| -> TestResult<Vec<String>> {
        let connection = history(data)?;
        let mut statement =
            connection.prepare("SELECT message_id FROM usage_events ORDER BY message_id")?;
        let ids = statement.query_map([], |row| row.get::<_, String>(0))?;
        Ok(ids.collect::<Result<_, _>>()?)
    };
    let contiguous = |ids: &[String]| {
        ids.iter()
            .enumerate()
            .all(|(index, id)| *id == format!("m-{index:05}"))
    };
    let first = engine.pass(consented(), 1);
    assert_eq!(first.outcome, PassOutcome::CatchingUp, "{first:?}");
    let after_first = published_ids(&data)?;
    assert!(
        !after_first.is_empty() && after_first.len() < 3_000,
        "interrupted inside the table: {}",
        after_first.len()
    );
    assert!(
        contiguous(&after_first),
        "only whole groups, in rowid order"
    );
    let cursor: String = scalar(&data, "SELECT working_cursor_key FROM opencode_progress")?;
    let cursor: Value = serde_json::from_str(&cursor)?;
    assert_eq!(
        cursor["legacy"]["rowid"].as_i64(),
        Some(after_first.len() as i64),
        "the cursor is exactly after the last published group: {cursor}"
    );
    let second = engine.pass(consented(), 2);
    let after_second = published_ids(&data)?;
    assert!(
        after_second.len() > after_first.len() && contiguous(&after_second),
        "the next pass resumes from the cursor: {} then {}",
        after_first.len(),
        after_second.len()
    );
    assert_eq!(second.outcome, PassOutcome::CatchingUp, "{second:?}");
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Fairness, staging rollback, sticky errors, failed-file retry, last-good
// ---------------------------------------------------------------------------------------------

fn scalar<T: rusqlite::types::FromSql>(data: &Path, sql: &str) -> TestResult<T> {
    Ok(history(data)?.query_row(sql, [], |row| row.get(0))?)
}

fn bulk_legacy(path: &Path, rows: u32, input: u64) -> TestResult<Connection> {
    let c = open_fixture(path)?;
    let tx = c.unchecked_transaction()?;
    let payload = serde_json::to_vec(&json!({
        "role": "assistant",
        "tokens": counts(Some(input), Some(0), Some(0), Some(0), Some(0), None)
    }))?;
    for index in 0..rows {
        tx.execute(
            "INSERT INTO message(id, session_id, time_created, data) VALUES (?1, 's', ?2, ?3)",
            rusqlite::params![format!("m-{index:05}"), T0 + i64::from(index), payload],
        )?;
    }
    tx.commit()?;
    Ok(c)
}

#[test]
fn known_current_record_is_read_first_behind_a_large_historical_backlog() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(&directory.path().canonicalize()?)?;
    write_json_message(
        &source,
        "s",
        "current",
        T0,
        Some(counts(Some(1), Some(0), Some(0), Some(0), Some(0), None)),
    )?;
    let mut engine = open_engine(&source, &data, &home)?;
    assert_eq!(engine.pass(consented(), 1).outcome, PassOutcome::Consistent);
    assert_eq!(
        find(&engine.observations()?, "current").input.value,
        Some(1)
    );

    // More historical entries than one pass may yield, and the live record changes.
    for dir in 0..11 {
        let crowded = source.join(format!("crowd-{dir:02}"));
        std::fs::create_dir(&crowded)?;
        for file in 0..1_900 {
            std::fs::write(crowded.join(format!("e{file:04}")), [])?;
        }
    }
    write_json_message(
        &source,
        "s",
        "current",
        T0,
        Some(counts(Some(2), Some(0), Some(0), Some(0), Some(0), None)),
    )?;
    let first = engine.pass(consented(), 2);
    assert_eq!(first.outcome, PassOutcome::CatchingUp, "{first:?}");
    assert_eq!(first.counters.entries, 20_000, "the entry ceiling is exact");
    assert_eq!(
        find(&engine.observations()?, "current").input.value,
        Some(2),
        "the current record is counted in the first capped pass"
    );
    assert_eq!(find(&engine.observations()?, "current").revision, 2);
    let reports = run_until_consistent(&mut engine, 3, 8);
    assert_eq!(
        reports.last().ok_or("pass")?.outcome,
        PassOutcome::Consistent
    );
    assert_eq!(
        find(&engine.observations()?, "current").revision,
        2,
        "no duplicate revision"
    );
    Ok(())
}

#[test]
fn staging_failure_keeps_the_durable_frontier_and_never_completes_falsely() -> TestResult {
    let _guard = vfs_test_guard();
    for point in [
        quotern_core::store::FaultPoint::BeforeCommit,
        quotern_core::store::FaultPoint::AfterCommit,
    ] {
        let directory = tempdir()?;
        let (source, data, home) = source_roots(directory.path())?;
        let _c = bulk_legacy(&source.join("opencode.db"), 5_001, 1)?;
        let admitted = i64::try_from(admission_rows(&source.join("opencode.db"))?)?;
        let mut engine = open_engine(&source, &data, &home)?;
        let first = engine.pass(consented(), 1);
        assert_eq!(first.outcome, PassOutcome::CatchingUp);
        assert_eq!(first.last_good_ms, Some(1));
        let spool: i64 = scalar(&data, "SELECT COUNT(*) FROM opencode_candidate_spool")?;
        assert_eq!(
            spool,
            4_999 - admitted,
            "the 5,000th row had no budget left for its part lookup"
        );

        engine.inject_commit_fault(point);
        let failed = engine.pass(consented(), 2);
        assert_eq!(
            failed.outcome,
            PassOutcome::Partial,
            "{point:?}: {failed:?}"
        );
        assert_eq!(failed.failure, Some(FailureCode::Store));
        assert_ne!(
            failed.outcome,
            PassOutcome::Consistent,
            "a failed finalization is never complete"
        );
        match point {
            quotern_core::store::FaultPoint::BeforeCommit => {
                assert_eq!(
                    failed.last_good_ms,
                    Some(1),
                    "no certification of unpublished work"
                );
                // The rolled-back finalization invalidated its acquisition evidence: the staged
                // candidates and the completed-database cursor are gone, so every source is
                // read again before anything can be certified; published history stays.
                assert_eq!(
                    scalar::<i64>(&data, "SELECT COUNT(*) FROM opencode_progress")?,
                    0
                );
                assert_eq!(
                    scalar::<i64>(&data, "SELECT COUNT(*) FROM opencode_candidate_spool")?,
                    0
                );
                assert_eq!(scalar::<i64>(&data, "SELECT generation FROM sources")?, 0);
                assert_eq!(
                    engine.snapshot(&failed)?.projection.records,
                    u64::try_from(4_999 - admitted)?
                );
            }
            quotern_core::store::FaultPoint::AfterCommit => {
                assert_eq!(
                    engine.snapshot(&failed)?.projection.records,
                    5_001,
                    "the commit did happen"
                );
                assert_eq!(scalar::<i64>(&data, "SELECT generation FROM sources")?, 1);
            }
        }
        drop(engine);
        let mut engine = open_engine(&source, &data, &home)?;
        let reports = run_until_consistent(&mut engine, 3, 6);
        assert_eq!(
            reports.last().ok_or("pass")?.outcome,
            PassOutcome::Consistent,
            "{point:?}"
        );
        let projection = engine.snapshot(reports.last().ok_or("pass")?)?.projection;
        assert_eq!(projection.records, 5_001, "{point:?}");
        assert_eq!(
            projection.input.value,
            Some(5_001),
            "{point:?}: nothing lost or duplicated"
        );
        assert_eq!(
            scalar::<i64>(&data, "SELECT MAX(revision) FROM usage_events")?,
            1,
            "{point:?}: reacquisition republishes identical values without revising"
        );
    }
    Ok(())
}

#[test]
fn spool_capacity_failure_rolls_back_and_preserves_the_durable_frontier() -> TestResult {
    let directory = tempdir()?;
    let root = directory.path().join("root");
    std::fs::create_dir_all(&root)?;
    let mut store = quotern_core::store::Store::open(&directory.path().join("data"))?;
    let registration =
        store.register_source(&root, quotern_core::domain::SourceKind::Custom, (1, 1))?;
    let frontier = [(root.join("kept"), 1_usize, false)];
    let small = [quotern_core::store::SpoolFile {
        relative_path: PathBuf::from("a"),
        device: 1,
        inode: 1,
        size: 1,
        mtime_ns: 1,
        parser_kind: "sqlite".to_owned(),
    }];
    store.stage_scan(files_request(&registration, &root, &small, &frontier))?;
    let durable = store.load_frontier(&registration.source_id, &root, registration.generation)?;
    assert_eq!(durable.len(), 1);

    // 200_001 metadata rows: one over the row ceiling.
    let many = (0..200_001_u64)
        .map(|index| quotern_core::store::SpoolFile {
            relative_path: PathBuf::from(format!("f{index}")),
            device: 1,
            inode: index,
            size: 0,
            mtime_ns: 0,
            parser_kind: "sqlite".to_owned(),
        })
        .collect::<Vec<_>>();
    let other = [(root.join("moved"), 1_usize, false)];
    let rejected = store.stage_scan(files_request(&registration, &root, &many, &other));
    assert_eq!(
        rejected.err(),
        Some(quotern_core::store::StoreError::LimitExceeded)
    );
    assert_eq!(
        store.load_frontier(&registration.source_id, &root, registration.generation)?,
        durable,
        "the rolled-back stage left the durable frontier untouched"
    );
    // 64 MiB of path text in far fewer rows: the byte ceiling.
    let long = (0..17_000_u64)
        .map(|index| quotern_core::store::SpoolFile {
            relative_path: PathBuf::from(format!("{index:05}{}", "a".repeat(4_000))),
            device: 1,
            inode: index,
            size: 0,
            mtime_ns: 0,
            parser_kind: "sqlite".to_owned(),
        })
        .collect::<Vec<_>>();
    let rejected = store.stage_scan(files_request(&registration, &root, &long, &other));
    assert_eq!(
        rejected.err(),
        Some(quotern_core::store::StoreError::LimitExceeded)
    );
    assert_eq!(
        store.load_frontier(&registration.source_id, &root, registration.generation)?,
        durable
    );
    // A path beyond the 4096-byte ceiling is refused outright.
    let too_long = [quotern_core::store::SpoolFile {
        relative_path: PathBuf::from("b".repeat(4_097)),
        ..small[0].clone()
    }];
    assert_eq!(
        store
            .stage_scan(files_request(&registration, &root, &too_long, &frontier))
            .err(),
        Some(quotern_core::store::StoreError::InvalidRelativePath)
    );
    Ok(())
}

fn files_request<'a>(
    registration: &'a quotern_core::store::SourceRegistration,
    root: &'a Path,
    files: &'a [quotern_core::store::SpoolFile],
    frontier: &'a [(PathBuf, usize, bool)],
) -> quotern_core::store::StageRequest<'a> {
    let batch = quotern_core::store::StageBatch {
        files,
        ..Default::default()
    };
    store_request(registration, root, batch, frontier)
}

fn store_request<'a>(
    registration: &'a quotern_core::store::SourceRegistration,
    root: &'a Path,
    batch: quotern_core::store::StageBatch<'a>,
    frontier: &'a [(PathBuf, usize, bool)],
) -> quotern_core::store::StageRequest<'a> {
    quotern_core::store::StageRequest {
        source_id: &registration.source_id,
        root,
        generation: registration.generation,
        batch,
        frontier: Some(frontier),
        outcome: PassOutcome::CatchingUp,
        failure: None,
        rejection: None,
        backoff: None,
        stable_read: false,
        counters: Default::default(),
        now_ms: 1,
    }
}

#[test]
fn rejected_first_page_stays_unresolved_through_eof_and_reopen() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let c = bulk_legacy(&source.join("opencode.db"), 5_001, 1)?;
    c.execute("UPDATE message SET data = x'7b' WHERE id = 'm-00000'", [])?;
    let mut engine = open_engine(&source, &data, &home)?;
    let first = engine.pass(consented(), 1);
    assert_eq!(first.outcome, PassOutcome::CatchingUp, "{first:?}");
    assert_eq!(first.counters.rejected_records, 1);
    assert_eq!(
        scalar::<String>(&data, "SELECT generation_failure FROM sources")?,
        "invalid_record",
        "the rejection is persisted, not recreated per pass"
    );
    drop(engine);
    let mut engine = open_engine(&source, &data, &home)?;
    let mut last = engine.pass(consented(), 2);
    if last.counters.rows_read == 0 {
        last = engine.pass(consented(), 3);
    }
    // The final page is clean, but the sweep as a whole had a rejection.
    assert_eq!(last.counters.rejected_records, 0, "{last:?}");
    assert_eq!(last.outcome, PassOutcome::Partial, "{last:?}");
    assert_eq!(last.failure, Some(FailureCode::InvalidRecord));
    assert_eq!(engine.snapshot(&last)?.projection.records, 5_000);
    // Repairing the row lets a later complete sweep resolve it.
    c.execute(
        "UPDATE message SET data = ?1 WHERE id = 'm-00000'",
        [serde_json::to_vec(&json!({"role": "assistant", "tokens": counts(Some(1), Some(0), Some(0), Some(0), Some(0), None)}))?],
    )?;
    let reports = run_until_consistent(&mut engine, 10, 6);
    let done = reports.last().ok_or("pass")?;
    assert_eq!(done.outcome, PassOutcome::Consistent, "{reports:?}");
    assert_eq!(done.failure, None);
    assert_eq!(engine.snapshot(done)?.projection.records, 5_001);
    Ok(())
}

#[test]
fn failed_file_retry_is_separate_from_siblings_and_order_independent() -> TestResult {
    let _guard = vfs_test_guard();
    let mut outcomes = Vec::new();
    for junk_first in [true, false] {
        let directory = tempdir()?;
        let (source, data, home) = source_roots(directory.path())?;
        let (junk, good) = if junk_first {
            ("opencode-a.db", "opencode-z.db")
        } else {
            ("opencode-z.db", "opencode-a.db")
        };
        std::fs::write(source.join(junk), b"definitely not sqlite")?;
        let c = open_fixture(&source.join(good))?;
        put_message(
            &c,
            "good",
            "s",
            T0,
            &json!({"role": "assistant", "tokens": counts(Some(7), None, None, None, None, None)}),
        )?;
        drop(c);
        write_json_message(
            &source,
            "sj",
            "sibling",
            T0,
            Some(counts(Some(3), None, None, None, None, None)),
        )?;
        let mut engine = open_engine(&source, &data, &home)?;
        let report = engine.pass(consented(), 1);
        outcomes.push((report.outcome, report.failure, report.records_committed));
        assert_eq!(
            report.outcome,
            PassOutcome::Unavailable,
            "{junk_first}: {report:?}"
        );
        assert_eq!(report.failure, Some(FailureCode::NotSqlite));
        // The frozen outcome table: an unavailable pass publishes no rows, whatever siblings
        // were readable; their numbers arrive only with a pass that is not unavailable.
        assert_eq!(report.records_committed, 0);
        let projection = engine.snapshot(&report)?.projection;
        assert_eq!((projection.records, projection.input.value), (0, None));
        assert_eq!(
            report.last_good_ms, None,
            "no last-good on an unavailable pass"
        );
        assert_eq!(
            scalar::<i64>(&data, "SELECT COUNT(*) FROM acquisition_failures")?,
            1
        );
        drop(engine);

        // The failure survives a restart and is retried every pass without blocking siblings.
        let mut engine = open_engine(&source, &data, &home)?;
        let mut again = engine.pass(consented(), 2);
        if again.counters.entries == 0 {
            again = engine.pass(consented(), 3);
        }
        assert_eq!(again.outcome, PassOutcome::Unavailable, "{again:?}");
        assert_eq!(
            again.counters.header_reads, 2,
            "junk and valid databases each probed once"
        );
        // Replacing the junk with a valid database resolves the failure.
        std::fs::remove_file(source.join(junk))?;
        let replacement = open_fixture(&source.join(junk))?;
        put_message(
            &replacement,
            "other",
            "s",
            T0,
            &json!({"role": "assistant", "tokens": counts(Some(1), None, None, None, None, None)}),
        )?;
        drop(replacement);
        let reports = run_until_consistent(&mut engine, 10, 4);
        assert_eq!(
            reports.last().ok_or("pass")?.outcome,
            PassOutcome::Consistent,
            "{reports:?}"
        );
        assert_eq!(
            scalar::<i64>(&data, "SELECT COUNT(*) FROM acquisition_failures")?,
            0
        );
        assert_eq!(
            engine
                .snapshot(reports.last().ok_or("pass")?)?
                .projection
                .input
                .value,
            Some(11)
        );
    }
    assert_eq!(
        outcomes[0], outcomes[1],
        "outcome does not depend on traversal order"
    );
    Ok(())
}

#[test]
fn acquisition_failure_marks_retained_groups_pending_with_its_reason() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let database = source.join("opencode.db");
    let c = open_fixture(&database)?;
    put_message(
        &c,
        "kept",
        "s",
        T0,
        &json!({"role": "assistant", "tokens": counts(Some(5), None, None, None, None, None)}),
    )?;
    drop(c);
    let original = std::fs::read(&database)?;
    let mut engine = open_engine(&source, &data, &home)?;
    assert_eq!(engine.pass(consented(), 1).outcome, PassOutcome::Consistent);
    assert!(!find(&engine.observations()?, "kept").pending_partial);

    std::fs::write(&database, b"overwritten with junk")?;
    let failed = engine.pass(consented(), 2);
    assert_eq!(failed.outcome, PassOutcome::Unavailable, "{failed:?}");
    assert_eq!(failed.failure, Some(FailureCode::NotSqlite));
    assert_eq!(failed.last_good_ms, Some(1), "last-good is retained");
    let kept = engine.observations()?.remove(0);
    assert_eq!(kept.input.value, Some(5), "the prior value stays visible");
    assert!(kept.pending_partial);
    assert_eq!(kept.pending_reason, Some(FailureCode::NotSqlite));
    assert_eq!(kept.input.status, ObservationStatus::Partial);

    std::fs::write(&database, &original)?;
    let healed = engine.pass(consented(), 3);
    assert_eq!(healed.outcome, PassOutcome::Consistent, "{healed:?}");
    let kept = engine.observations()?.remove(0);
    assert!(!kept.pending_partial && kept.pending_reason.is_none());
    assert_eq!(kept.revision, 1);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Source change retry/backoff, generation admission, JSON consistency, discard propagation
// ---------------------------------------------------------------------------------------------

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// A recording filesystem that, while `swap` is set, replaces the database inode between the
/// engine's preflight and SQLite's open, so the identity set differs before and after the read.
fn swapping_fs(database: &Path, swap: &Arc<AtomicBool>) -> RecordingFs {
    let fs = RecordingFs::new();
    let (target, flag) = (database.to_path_buf(), Arc::clone(swap));
    fs.on_boundary(move |kind, _| {
        if kind == OpenKind::Sqlite && flag.load(Ordering::SeqCst) {
            let copy = target.with_extension("swap");
            std::fs::copy(&target, &copy).expect("copy database");
            std::fs::rename(&copy, &target).expect("replace database inode");
        }
    });
    fs
}

fn retry_state(data: &Path) -> TestResult<(i64, Option<i64>, i64)> {
    Ok(history(data)?.query_row(
        "SELECT change_count, next_retry_ms, dirty FROM sources",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?)
}

#[test]
fn source_change_retries_back_off_then_become_unavailable_and_recover() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(&directory.path().canonicalize()?)?;
    let database = source.join("opencode.db");
    let c = open_fixture(&database)?;
    put_message(
        &c,
        "kept",
        "s",
        T0,
        &json!({"role": "assistant", "tokens": counts(Some(4), None, None, None, None, None)}),
    )?;
    drop(c);
    let swap = Arc::new(AtomicBool::new(false));
    let fs = swapping_fs(&database, &swap);
    let mut opens = fs.clone();
    let mut engine = open_recording_engine(fs, &source, &data, &home)
        .map_err(|report| format!("open failed: {report:?}"))?;
    let baseline = engine.pass(consented(), 0);
    assert_eq!(baseline.outcome, PassOutcome::Consistent, "{baseline:?}");
    assert_eq!(baseline.last_good_ms, Some(0));
    assert_eq!(opens.metrics().sqlite_opens, 1);

    swap.store(true, Ordering::SeqCst);
    let mut physical = opens.metrics().sqlite_opens;
    // (clock, expected outcome, whether the source is physically opened)
    let timeline = [
        (1_000_i64, PassOutcome::Partial, true), // change 1: retry at +5s
        (5_999, PassOutcome::Partial, false),    // too early: no source I/O
        (6_000, PassOutcome::Partial, true),     // change 2: retry at +10s
        (15_999, PassOutcome::Partial, false),
        (16_000, PassOutcome::Unavailable, true), // change 3: unavailable, retry at +20s
        (35_999, PassOutcome::Unavailable, false),
    ];
    for (now, outcome, opened) in timeline {
        let report = engine.pass(consented(), now);
        assert_eq!(report.outcome, outcome, "t={now}: {report:?}");
        assert_eq!(report.failure, Some(FailureCode::SourceChanging), "t={now}");
        assert_eq!(report.records_committed, 0, "t={now}");
        assert_eq!(report.last_good_ms, Some(0), "t={now}: last-good retained");
        let now_opens = opens.metrics().sqlite_opens;
        assert_eq!(now_opens > physical, opened, "t={now}: physical opens");
        physical = now_opens;
        if !opened {
            assert_eq!(
                report.counters,
                Default::default(),
                "t={now}: gated passes do no I/O"
            );
        }
        if now == 6_000 {
            // The retry state is durable: a reopened engine still waits out the deadline.
            let fs = swapping_fs(&database, &swap);
            let observed = fs.clone();
            let reopened = open_recording_engine(fs, &source, &data, &home)
                .map_err(|report| format!("reopen failed: {report:?}"))?;
            drop(engine);
            engine = reopened;
            let early = engine.pass(consented(), 15_999);
            assert_eq!(early.counters, Default::default());
            assert_eq!(
                observed.metrics().sqlite_opens,
                0,
                "reopen keeps the backoff"
            );
            opens = observed;
            physical = 0;
        }
    }
    assert_eq!(retry_state(&data)?, (3, Some(16_000 + 20_000), 1));
    let kept = engine.observations()?.remove(0);
    assert_eq!(
        kept.input.value,
        Some(4),
        "history survives repeated changes"
    );
    assert!(kept.pending_partial);
    assert_eq!(kept.pending_reason, Some(FailureCode::SourceChanging));

    // Stable again: the next attempt after the deadline succeeds and resets the counters.
    swap.store(false, Ordering::SeqCst);
    let recovered = engine.pass(consented(), 36_000);
    assert_eq!(recovered.outcome, PassOutcome::Consistent, "{recovered:?}");
    assert_eq!(retry_state(&data)?, (0, None, 0));
    assert!(!engine.observations()?.remove(0).pending_partial);
    Ok(())
}

#[test]
fn source_change_backoff_doubles_to_the_five_minute_cap() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(&directory.path().canonicalize()?)?;
    let database = source.join("opencode.db");
    let c = open_fixture(&database)?;
    put_message(
        &c,
        "kept",
        "s",
        T0,
        &json!({"role": "assistant", "tokens": counts(Some(4), None, None, None, None, None)}),
    )?;
    drop(c);
    let swap = Arc::new(AtomicBool::new(true));
    let fs = swapping_fs(&database, &swap);
    let mut engine = open_recording_engine(fs, &source, &data, &home)
        .map_err(|report| format!("open failed: {report:?}"))?;
    let mut now = 0_i64;
    let mut delays = Vec::new();
    for _ in 0..9 {
        engine.pass(consented(), now);
        let (_, next, _) = retry_state(&data)?;
        let next = next.ok_or("a retry deadline is scheduled")?;
        delays.push(next - now);
        now = next;
    }
    assert_eq!(
        delays,
        [
            5_000, 10_000, 20_000, 40_000, 80_000, 160_000, 300_000, 300_000, 300_000
        ]
    );
    Ok(())
}

#[test]
fn stale_generation_cannot_mutate_durable_state() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(&directory.path().canonicalize()?)?;
    write_json_message(
        &source,
        "s",
        "m",
        T0,
        Some(counts(Some(1), Some(0), Some(0), Some(0), Some(0), None)),
    )?;
    let mut first = open_engine(&source, &data, &home)?;
    let mut second = open_engine(&source, &data, &home)?;
    assert_eq!(first.pass(consented(), 1).outcome, PassOutcome::Consistent);
    let before = scalar::<i64>(&data, "SELECT MAX(revision) FROM usage_events")?;
    // The second engine still holds the pre-commit generation: its writes are refused.
    let stale = second.pass(consented(), 2);
    assert_eq!(stale.outcome, PassOutcome::Partial, "{stale:?}");
    assert_eq!(stale.failure, Some(FailureCode::Store));
    assert_eq!(
        scalar::<i64>(&data, "SELECT MAX(revision) FROM usage_events")?,
        before
    );
    assert_eq!(scalar::<i64>(&data, "SELECT generation FROM sources")?, 1);
    // It reloads the durable generation and then proceeds normally.
    let healed = second.pass(consented(), 3);
    assert_eq!(healed.outcome, PassOutcome::Consistent, "{healed:?}");
    assert_eq!(scalar::<i64>(&data, "SELECT generation FROM sources")?, 2);
    assert_eq!(
        scalar::<i64>(&data, "SELECT COUNT(*) FROM usage_events")?,
        1
    );

    // Every mutating store API enforces the same expected generation.
    let root = source.clone();
    let mut store = quotern_core::store::Store::open(&data)?;
    let id = store.source_id(&root)?.ok_or("registered")?;
    let stale_generation = 0;
    let stage = quotern_core::store::StageRequest {
        source_id: &id,
        root: &root,
        generation: stale_generation,
        batch: Default::default(),
        frontier: Some(&[]),
        outcome: PassOutcome::CatchingUp,
        failure: None,
        rejection: None,
        backoff: None,
        stable_read: false,
        counters: Default::default(),
        now_ms: 9,
    };
    assert_eq!(
        store.stage_scan(stage).err(),
        Some(quotern_core::store::StoreError::StaleGeneration)
    );
    let commit = quotern_core::store::CommitRequest {
        source_id: &id,
        root: &root,
        generation: stale_generation,
        batch: Default::default(),
        outcome: PassOutcome::Consistent,
        failure: None,
        rejection: None,
        terminal: true,
        counters: Default::default(),
        now_ms: 9,
    };
    assert_eq!(
        store.commit_generation(commit).err(),
        Some(quotern_core::store::StoreError::StaleGeneration)
    );
    let discard = quotern_core::store::DiscardRequest {
        source_id: &id,
        generation: stale_generation,
        failure: FailureCode::SourceChanging,
        paths: &[],
        conflicts: &[],
        counters: Default::default(),
        now_ms: 9,
    };
    assert_eq!(
        store.discard_generation(discard).err(),
        Some(quotern_core::store::StoreError::StaleGeneration)
    );
    assert_eq!(
        store.reset_acquisition(&id, stale_generation).err(),
        Some(quotern_core::store::StoreError::StaleGeneration)
    );
    assert_eq!(scalar::<i64>(&data, "SELECT change_count FROM sources")?, 0);
    Ok(())
}

#[test]
fn json_group_mutating_during_acquisition_is_not_published() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(&directory.path().canonicalize()?)?;
    let message = source.join("storage/message/s/group.json");
    write_json_message(&source, "s", "group", T0, None)?;
    let part = |input: u64| {
        step_finish(counts(
            Some(input),
            Some(0),
            Some(0),
            Some(0),
            Some(0),
            Some(input),
        ))
    };
    write_json_part(&source, "group", "p1", &part(10))?;
    let mut engine = open_engine(&source, &data, &home)?;
    assert_eq!(engine.pass(consented(), 1).outcome, PassOutcome::Consistent);
    assert_eq!(find(&engine.observations()?, "group").total.value, Some(10));

    // The parts change, and the message itself changes between its read and the part reads.
    write_json_part(&source, "group", "p1", &part(20))?;
    let fs = RecordingFs::new();
    let (target, mutated, armed) = (
        source.join("storage/part/group/p1.json"),
        message.clone(),
        Arc::new(AtomicBool::new(true)),
    );
    let flag = Arc::clone(&armed);
    fs.on_boundary(move |kind, path| {
        if kind == OpenKind::Bounded && path == target && flag.swap(false, Ordering::SeqCst) {
            std::fs::write(
                &mutated,
                serde_json::to_vec(&json!({"role": "assistant", "time": {"created": T0}, "content": "rewritten mid-read"})).expect("json"),
            )
            .expect("rewrite message");
        }
    });
    let engine = open_recording_engine(fs, &source, &data, &home)
        .map_err(|report| format!("open failed: {report:?}"))?;
    let (mut engine, report) = pass_within(engine, 2, 10)?;
    assert_eq!(report.outcome, PassOutcome::Partial, "{report:?}");
    assert_eq!(report.failure, Some(FailureCode::SourceChanging));
    let kept = find(&engine.observations()?, "group").clone();
    assert_eq!(
        kept.total.value,
        Some(10),
        "the mixed generation is not published"
    );
    assert!(kept.pending_partial);
    assert_eq!(kept.pending_reason, Some(FailureCode::SourceChanging));
    assert_eq!(
        scalar::<String>(&data, "SELECT code FROM acquisition_failures")?,
        "source_changing"
    );

    // Once the files stop moving, the group is acquired whole and the failure clears.
    let reports = run_until_consistent(&mut engine, 10, 4);
    assert_eq!(
        reports.last().ok_or("pass")?.outcome,
        PassOutcome::Consistent,
        "{reports:?}"
    );
    let settled = find(&engine.observations()?, "group").clone();
    assert_eq!(settled.total.value, Some(20));
    assert!(!settled.pending_partial);
    assert_eq!(
        scalar::<i64>(&data, "SELECT COUNT(*) FROM acquisition_failures")?,
        0
    );
    Ok(())
}

#[test]
fn failed_discard_is_a_store_failure_not_a_pretended_invalidation() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(&directory.path().canonicalize()?)?;
    let database = source.join("opencode.db");
    let c = open_fixture(&database)?;
    put_message(
        &c,
        "kept",
        "s",
        T0,
        &json!({"role": "assistant", "tokens": counts(Some(4), None, None, None, None, None)}),
    )?;
    drop(c);
    let swap = Arc::new(AtomicBool::new(false));
    let fs = swapping_fs(&database, &swap);
    let mut engine = open_recording_engine(fs, &source, &data, &home)
        .map_err(|report| format!("open failed: {report:?}"))?;
    assert_eq!(engine.pass(consented(), 0).outcome, PassOutcome::Consistent);
    let before = (
        scalar::<i64>(&data, "SELECT generation FROM sources")?,
        retry_state(&data)?,
        scalar::<i64>(&data, "SELECT pending_partial FROM usage_events")?,
    );

    swap.store(true, Ordering::SeqCst);
    engine.inject_commit_fault(quotern_core::store::FaultPoint::BeforeCommit);
    let report = engine.pass(consented(), 1_000);
    assert_eq!(report.failure, Some(FailureCode::Store), "{report:?}");
    assert_ne!(report.failure, Some(FailureCode::SourceChanging));
    let after = (
        scalar::<i64>(&data, "SELECT generation FROM sources")?,
        retry_state(&data)?,
        scalar::<i64>(&data, "SELECT pending_partial FROM usage_events")?,
    );
    assert_eq!(before, after, "nothing was invalidated or scheduled");

    // The same change is then handled for real, with the cleanup committed.
    let handled = engine.pass(consented(), 2_000);
    assert_eq!(
        handled.failure,
        Some(FailureCode::SourceChanging),
        "{handled:?}"
    );
    assert_eq!(retry_state(&data)?.0, 1);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Persisted-shape oracles: producer -> Store column -> consumer, with independent expectations
// ---------------------------------------------------------------------------------------------

fn analytics_db(data: &Path) -> TestResult<Connection> {
    Ok(Connection::open(data.join("history.sqlite"))?)
}

#[test]
fn saved_cursor_keeps_exact_row_identities_and_resumes_the_consumer() -> TestResult {
    let _guard = vfs_test_guard();
    // Above 2^53: any floating-point intermediate would round these row identities.
    const BASE: i64 = 9_007_199_254_740_993;
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let c = open_fixture(&source.join("opencode.db"))?;
    let tx = c.unchecked_transaction()?;
    let payload = serde_json::to_vec(&json!({
        "role": "assistant",
        "tokens": counts(Some(1), Some(2), Some(0), Some(0), Some(0), None)
    }))?;
    for index in 0..5_100_i64 {
        tx.execute(
            "INSERT INTO message(rowid, id, session_id, time_created, data) \
             VALUES (?1, ?2, 's', ?3, ?4)",
            rusqlite::params![
                BASE + index,
                format!("m-\u{e9}\"\\{index:05}"),
                T0 + index,
                payload
            ],
        )?;
    }
    tx.commit()?;
    drop(c);

    let admission = i64::try_from(admission_rows(&source.join("opencode.db"))?)?;
    let mut engine = open_engine(&source, &data, &home)?;
    let first = engine.pass(consented(), 1);
    assert_eq!(first.outcome, PassOutcome::CatchingUp, "{first:?}");
    assert_eq!(first.counters.rows_read, 5_000, "{first:?}");
    let saved: Vec<String> = {
        let history = analytics_db(&data)?;
        let mut statement = history.prepare(
            "SELECT working_cursor_key FROM opencode_progress WHERE working_cursor_key IS NOT NULL",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        rows.collect::<Result<_, _>>()?
    };
    assert_eq!(saved.len(), 1, "one saved keyset: {saved:?}");
    let cursor: Value = serde_json::from_str(&saved[0])?;
    assert_eq!(
        cursor["legacy"]["rowid"].as_i64(),
        Some(BASE + 4_998 - admission),
        "the exact last group completed, never a rounded one: {cursor}"
    );
    assert_eq!(cursor["legacy"]["done"], json!(false), "{cursor}");

    // A restart resumes from the saved keyset and the final totals are exact.
    drop(engine);
    let mut engine = open_engine(&source, &data, &home)?;
    let mut last = engine.pass(consented(), 2);
    for step in 0..4 {
        if last.outcome == PassOutcome::Consistent {
            break;
        }
        last = engine.pass(consented(), 3 + step);
    }
    assert_eq!(last.outcome, PassOutcome::Consistent, "{last:?}");
    let projection = engine.snapshot(&last)?.projection;
    assert_eq!(projection.records, 5_100);
    assert_eq!(projection.input.value, Some(5_100));
    assert_eq!(projection.output.value, Some(5_100 * 2));
    Ok(())
}

#[test]
fn an_undecodable_saved_cursor_is_an_explicit_failure_not_a_restart() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let c = bulk_legacy(&source.join("opencode.db"), 5_100, 1)?;
    drop(c);
    let mut engine = open_engine(&source, &data, &home)?;
    let first = engine.pass(consented(), 1);
    assert_eq!(first.outcome, PassOutcome::CatchingUp, "{first:?}");
    drop(engine);
    // A fractional row identity is not a supported keyset.
    let changed = analytics_db(&data)?.execute(
        "UPDATE opencode_progress SET working_cursor_key = \
         '{\"legacy\":{\"rowid\":1.5,\"done\":false},\"v2\":{\"rowid\":null,\"done\":false}}' \
         WHERE working_cursor_key IS NOT NULL",
        [],
    )?;
    assert_eq!(changed, 1);
    let mut engine = open_engine(&source, &data, &home)?;
    let mut report = engine.pass(consented(), 2);
    // The first pass after a reopen only reconstructs unfinished directories.
    if report.counters.rows_read == 0 && report.outcome == PassOutcome::Partial {
        report = engine.pass(consented(), 3);
    }
    assert_ne!(report.outcome, PassOutcome::Consistent, "{report:?}");
    assert!(report.failure.is_some(), "{report:?}");
    Ok(())
}

#[test]
fn staged_candidates_keep_every_optional_value_exactly_through_a_store_reopen() -> TestResult {
    use quotern_core::domain::{RecordCandidate, SourceKind, TokenComponents};
    use quotern_core::store::{StageBatch, Store};
    let directory = tempdir()?;
    let root = directory.path().join("root");
    std::fs::create_dir_all(&root)?;
    let data = directory.path().join("data");
    let mut store = Store::open(&data)?;
    let registration = store.register_source(&root, SourceKind::Custom, (1, 1))?;
    let cap = 1_000_000_000_000_u64;
    let latest = 253_402_207_200_999_i64;
    let path = root.join("opencode.db");
    let make = |message: &str,
                components: TokenComponents,
                total: Option<u64>,
                parts: &[&str],
                at: i64,
                fingerprint: u64| RecordCandidate {
        session_id: "s\u{e9}\"\\".to_owned(),
        message_id: message.to_owned(),
        occurred_at_ms: at,
        total: quotern_core::domain::resolve_total(&components, total).0,
        total_provenance: quotern_core::domain::resolve_total(&components, total).1,
        source_convention: quotern_core::domain::resolve_total(&components, total).2,
        acquisition_consistency:
            quotern_core::domain::AcquisitionConsistency::SqliteReadTransaction,
        components,
        selected_part_ids: parts.iter().map(|part| (*part).to_owned()).collect(),
        pending_partial: !parts.is_empty(),
        canonical_path: path.clone(),
        format_rank: 1,
        fingerprint,
    };
    let component = |value: Option<u64>| TokenComponents {
        input: value,
        output: value,
        reasoning: value,
        cache_read: value,
        cache_write: value,
    };
    let candidates = vec![
        // Absent is not zero: nothing reported at all.
        make("absent", component(None), None, &[], 0, 0),
        // Explicit zero in every slot, including the total.
        make("zero", component(Some(0)), Some(0), &[], 1, 1),
        // The normative cap and the extremes of the other integer domains.
        make(
            "cap",
            component(Some(cap)),
            Some(cap),
            &["a\"\u{e9}", "b\\\u{df}"],
            latest,
            u64::MAX,
        ),
        // Mixed: independent slots keep their own presence.
        make(
            "mixed",
            TokenComponents {
                input: Some(0),
                output: None,
                reasoning: Some(cap - 1),
                cache_read: None,
                cache_write: Some(cap - 2),
            },
            None,
            &["p\u{1F600}"],
            T0,
            9_007_199_254_740_993,
        ),
    ];
    let batch = StageBatch {
        candidates: &candidates,
        ..Default::default()
    };
    store.stage_scan(store_request(&registration, &root, batch, &[]))?;
    drop(store);

    let store = Store::open(&data)?;
    let mut loaded =
        store.load_staged_candidates(&registration.source_id, &root, registration.generation)?;
    let mut expected = candidates.clone();
    loaded.sort_by_key(RecordCandidate::record_id);
    expected.sort_by_key(RecordCandidate::record_id);
    assert_eq!(loaded, expected);
    drop(store);

    // A persisted candidate that does not match the supported shape is an explicit error.
    analytics_db(&data)?.execute(
        "UPDATE opencode_candidate_spool SET candidate_json = '{\"relative_path\":\"opencode.db\"}'",
        [],
    )?;
    let store = Store::open(&data)?;
    assert!(
        store
            .load_staged_candidates(&registration.source_id, &root, registration.generation)
            .is_err(),
        "malformed spool rows must fail, not load as empty"
    );
    Ok(())
}

#[test]
fn selected_part_ids_round_trip_through_a_reopen_with_escapes_and_empty_lists() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let c = open_fixture(&source.join("opencode.db"))?;
    let parent = serde_json::to_vec(&json!({
        "role": "assistant",
        "tokens": counts(Some(1), Some(1), Some(0), Some(0), Some(0), None)
    }))?;
    let part = serde_json::to_vec(&step_finish(counts(
        Some(10),
        Some(10),
        Some(0),
        Some(0),
        Some(0),
        None,
    )))?;
    for (id, at) in [("with-parts", T0), ("without-parts", T0 + 1)] {
        c.execute(
            "INSERT INTO message(id, session_id, time_created, data) VALUES (?1, 's', ?2, ?3)",
            rusqlite::params![id, at, parent],
        )?;
    }
    for part_id in ["b\\\u{df}", "a\"\u{e9}", "c\u{1F600}"] {
        c.execute(
            "INSERT INTO part(id, message_id, session_id, time_created, data) \
             VALUES (?1, 'with-parts', 's', 1, ?2)",
            rusqlite::params![part_id, part],
        )?;
    }
    drop(c);
    let mut engine = open_engine(&source, &data, &home)?;
    let report = engine.pass(consented(), 1);
    assert_eq!(report.outcome, PassOutcome::Consistent, "{report:?}");
    drop(engine);

    // Reopen: the durable column is decoded again by the observation consumer.
    let engine = open_engine(&source, &data, &home)?;
    let records = engine.observations()?;
    let by_message = |name: &str| {
        records
            .iter()
            .find(|record| record.message_id == name)
            .map(|record| (record.selected_part_ids.clone(), record.input.value))
    };
    assert_eq!(
        by_message("with-parts"),
        Some((
            vec![
                "a\"\u{e9}".to_owned(),
                "b\\\u{df}".to_owned(),
                "c\u{1F600}".to_owned()
            ],
            Some(30)
        ))
    );
    assert_eq!(
        by_message("without-parts"),
        Some((Vec::new(), Some(1))),
        "no parts is an empty list, distinct from unavailable membership"
    );
    assert!(records.iter().all(|record| !record.pending_partial));
    Ok(())
}

#[test]
fn next_pass_after_a_live_writer_commit_publishes_exact_new_totals() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let database = source.join("opencode.db");
    let mut writer = start_writer(&database)?;
    reset_vfs_metrics()?;
    let mut engine = open_engine(&source, &data, &home)?;
    let first = engine.pass(consented(), 1_700_000_002_000);
    assert_eq!(first.outcome, PassOutcome::Consistent, "{first:?}");
    let before = engine.snapshot(&first)?.projection;
    assert_eq!(
        (before.records, before.input.value, before.output.value),
        (1, Some(10), Some(20))
    );

    writer.command("append", "COMMITTED")?;
    let during = engine.snapshot(&first)?.projection;
    assert_eq!(
        during.input.value,
        Some(10),
        "no publication before the next pass"
    );

    let second = engine.pass(consented(), 1_700_000_003_000);
    assert_eq!(second.outcome, PassOutcome::Consistent, "{second:?}");
    let after = engine.snapshot(&second)?.projection;
    assert_eq!(after.records, 2);
    // 10+1 input, 20+1 output, reasoning 3+0, cache 4+0 / 5+0, from the two committed rows.
    assert_eq!(after.input.value, Some(11));
    assert_eq!(after.output.value, Some(21));
    assert_eq!(after.reasoning.value, Some(3));
    assert_eq!(after.cache_read.value, Some(4));
    assert_eq!(after.cache_write.value, Some(5));
    assert_vfs_read_only()?;
    writer.stop()?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Mirror precedence: format ranks, UTF-8 path order, direct-child and archive layout, additive
// fields and look-alike siblings.
// ---------------------------------------------------------------------------------------------

/// Acquires with an engine that is reopened between two passes, and returns the durable records
/// of the second.
fn acquire_twice(
    source: &Path,
    data: &Path,
    home: &Path,
) -> TestResult<(Vec<SourceReportedObservation>, PassReport)> {
    let mut engine = open_engine(source, data, home)?;
    engine.pass(consented(), 1);
    drop(engine);
    let mut engine = open_engine(source, data, home)?;
    let report = engine.pass(consented(), 2);
    Ok((engine.observations()?, report))
}

/// (message id, total, mirror conflict), ordered by message id.
fn winners(records: &[SourceReportedObservation]) -> Vec<(String, Option<u64>, bool)> {
    let mut winners: Vec<_> = records
        .iter()
        .map(|record| {
            (
                record.message_id.clone(),
                record.total.value,
                record.mirror_conflict,
            )
        })
        .collect();
    winners.sort();
    winners
}

/// Five-component usage whose derived total is `input`.
fn usage(input: u64) -> Value {
    counts(Some(input), Some(0), Some(0), Some(0), Some(0), None)
}

fn assistant(tokens: Value) -> Value {
    json!({"role": "assistant", "tokens": tokens})
}

fn persisted_ranks(data: &Path) -> TestResult<Vec<i64>> {
    let connection = history(data)?;
    let mut statement =
        connection.prepare("SELECT format_rank FROM reported_groups ORDER BY format_rank")?;
    Ok(statement
        .query_map([], |row| row.get(0))?
        .collect::<Result<Vec<i64>, _>>()?)
}

/// One record ID reported by any subset of the three layouts with different totals: the lowest
/// rank (legacy 0, v2 1, JSON 2) wins, a divergence is a visible conflict, identical values are
/// not, and the same answer holds after a reopen.
#[test]
fn every_format_rank_pairing_resolves_to_the_lowest_rank_after_reopen() -> TestResult {
    let _guard = vfs_test_guard();
    type Case = ([Option<u64>; 3], u64, bool, Vec<i64>);
    let cases: Vec<Case> = vec![
        ([Some(100), Some(200), Some(300)], 100, true, vec![0, 1, 2]),
        ([Some(100), Some(200), None], 100, true, vec![0, 1]),
        ([Some(100), None, Some(300)], 100, true, vec![0, 2]),
        ([None, Some(200), Some(300)], 200, true, vec![1, 2]),
        ([Some(100), None, None], 100, false, vec![0]),
        ([None, Some(200), None], 200, false, vec![1]),
        ([None, None, Some(300)], 300, false, vec![2]),
        ([Some(150), Some(150), Some(150)], 150, false, vec![0, 1, 2]),
    ];
    for (layouts, winner, conflict, ranks) in cases {
        let directory = tempdir()?;
        let (source, data, home) = source_roots(directory.path())?;
        let database = open_fixture(&source.join("opencode.db"))?;
        let [legacy, v2, json_total] = layouts;
        if let Some(total) = legacy {
            put_message(&database, "same", "ranked", T0, &assistant(usage(total)))?;
        }
        if let Some(total) = v2 {
            put_v2(
                &database,
                "same",
                "ranked",
                "assistant",
                1,
                T0,
                &json!({"tokens": usage(total)}),
            )?;
        }
        if let Some(total) = json_total {
            write_json_message(&source, "ranked", "same", T0, Some(usage(total)))?;
        }
        let (records, report) = acquire_twice(&source, &data, &home)?;
        assert_eq!(
            report.outcome,
            PassOutcome::Consistent,
            "{layouts:?}: {report:?}"
        );
        assert_eq!(
            winners(&records),
            [("same".to_owned(), Some(winner), conflict)],
            "{layouts:?}"
        );
        assert_eq!(records[0].revision, 1, "{layouts:?}");
        assert_eq!(persisted_ranks(&data)?, ranks, "{layouts:?}");
    }
    Ok(())
}

/// Same-rank mirrors are ordered by canonical UTF-8 bytes of the path, whatever the creation
/// order: not case-folded, not locale-collated and not UTF-16 ordered.
#[test]
fn same_rank_mirrors_resolve_by_utf8_path_bytes_in_either_creation_order() -> TestResult {
    let _guard = vfs_test_guard();
    let upper = "opencode-B.db"; // 0x42
    let lower = "opencode-a.db"; // 0x61
    let ascii_z = "opencode-z.db"; // 0x7a
    let latin = "opencode-\u{e9}.db"; // c3 a9
    let bmp_high = "opencode-\u{ff5e}.db"; // ef bd 9e: UTF-16 unit 0xff5e
    let astral = "opencode-\u{10000}.db"; // f0 90 80 80: UTF-16 units 0xd800 0xdc00
    let total_of = |name: &str| {
        [upper, lower, ascii_z, latin, bmp_high, astral]
            .iter()
            .position(|candidate| *candidate == name)
            .map(|index| 10 * (index as u64 + 1))
    };
    let scenarios: Vec<(Vec<&str>, &str)> = vec![
        (vec![ascii_z, latin], ascii_z),
        (vec![latin, bmp_high], latin),
        (vec![bmp_high, astral], bmp_high),
        (vec![lower, upper], upper),
        (vec![astral, bmp_high, latin, ascii_z, lower, upper], upper),
    ];
    for (present, winner) in scenarios {
        for reverse in [false, true] {
            let mut order = present.clone();
            if reverse {
                order.reverse();
            }
            let directory = tempdir()?;
            let (source, data, home) = source_roots(directory.path())?;
            let mut writers = Vec::new();
            for name in &order {
                let writer = open_fixture(&source.join(name))?;
                let total = total_of(name).ok_or("unknown name")?;
                put_message(&writer, "same", "paths", T0, &assistant(usage(total)))?;
                writers.push(writer);
            }
            let (records, report) = acquire_twice(&source, &data, &home)?;
            assert_eq!(
                report.outcome,
                PassOutcome::Consistent,
                "{present:?}: {report:?}"
            );
            assert_eq!(
                winners(&records),
                [("same".to_owned(), total_of(winner), true)],
                "{present:?} reversed={reverse}"
            );
        }
    }
    Ok(())
}

/// Databases are read as direct children of the source root and from archive subdirectories;
/// the same record ID resolves by full-path byte order (so `archive/` precedes `opencode.db`
/// and `zarchive/` follows it), and child sessions are never rolled up into their parents.
#[test]
fn direct_child_and_archived_databases_are_both_read_without_session_rollups() -> TestResult {
    let _guard = vfs_test_guard();
    for (archive, archive_wins) in [("archive", true), ("zarchive", false)] {
        let directory = tempdir()?;
        let (source, data, home) = source_roots(directory.path())?;
        std::fs::create_dir(source.join(archive))?;
        let direct = open_fixture(&source.join("opencode.db"))?;
        let archived = open_fixture(&source.join(archive).join("opencode.db"))?;
        put_message(&direct, "shared", "s", T0, &assistant(usage(100)))?;
        put_message(&direct, "direct-only", "s", T0, &assistant(usage(7)))?;
        put_message(&archived, "shared", "s", T0, &assistant(usage(200)))?;
        put_message(&archived, "archive-only", "s", T0, &assistant(usage(9)))?;
        let (records, report) = acquire_twice(&source, &data, &home)?;
        assert_eq!(
            report.outcome,
            PassOutcome::Consistent,
            "{archive}: {report:?}"
        );
        assert_eq!(
            winners(&records),
            [
                ("archive-only".to_owned(), Some(9), false),
                ("direct-only".to_owned(), Some(7), false),
                (
                    "shared".to_owned(),
                    Some(if archive_wins { 200 } else { 100 }),
                    true
                ),
            ],
            "{archive}"
        );
    }

    // A child session's usage stays on the child; the parent does not absorb it.
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let database = open_fixture(&source.join("opencode.db"))?;
    database.execute_batch(
        "INSERT INTO session(id, parent_id) VALUES ('parent', NULL), ('child', 'parent');\
         INSERT INTO session_v2(id, parent_id) VALUES ('v2-parent', NULL), ('v2-child', 'v2-parent');",
    )?;
    put_message(
        &database,
        "parent-message",
        "parent",
        T0,
        &assistant(usage(10)),
    )?;
    put_message(
        &database,
        "child-message",
        "child",
        T0,
        &assistant(usage(5)),
    )?;
    put_v2(
        &database,
        "v2-parent-message",
        "v2-parent",
        "assistant",
        1,
        T0,
        &json!({"tokens": usage(20)}),
    )?;
    put_v2(
        &database,
        "v2-child-message",
        "v2-child",
        "assistant",
        1,
        T0,
        &json!({"tokens": usage(3)}),
    )?;
    let (records, report) = acquire_twice(&source, &data, &home)?;
    assert_eq!(report.outcome, PassOutcome::Consistent, "{report:?}");
    let mut owners: Vec<_> = records
        .iter()
        .map(|record| (record.session_id.clone(), record.total.value))
        .collect();
    owners.sort();
    assert_eq!(
        owners,
        [
            ("child".to_owned(), Some(5)),
            ("parent".to_owned(), Some(10)),
            ("v2-child".to_owned(), Some(3)),
            ("v2-parent".to_owned(), Some(20)),
        ]
    );
    assert_eq!(
        records
            .iter()
            .filter_map(|record| record.total.value)
            .sum::<u64>(),
        38
    );
    Ok(())
}

/// Unknown additive fields anywhere in a record are ignored in every layout, while a malformed
/// field the product does read still rejects its record: tolerance is not blanket acceptance.
#[test]
fn additive_fields_are_ignored_in_every_layout_but_known_fields_stay_validated() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let database = open_fixture(&source.join("opencode.db"))?;
    let extras = json!({
        "input": 10, "output": 20, "reasoning": 3, "cache": {"read": 4, "write": 5, "future_cache": 99},
        "inputs": 99, "total_tokens": 99, "cost": 0.5, "future": {"nested": [1, 2, 3]}
    });
    let envelope = |tokens: Value| {
        json!({
            "role": "assistant", "providerID": "p", "modelID": "m", "finish": "stop",
            "cost": 1.5, "future_field": {"deep": null}, "tokens": tokens
        })
    };
    put_message(
        &database,
        "legacy-extra",
        "s1",
        T0,
        &envelope(extras.clone()),
    )?;
    put_v2(
        &database,
        "v2-extra",
        "s2",
        "assistant",
        1,
        T0,
        &json!({"unknown": [1], "tokens": extras.clone()}),
    )?;
    put_message(
        &database,
        "legacy-part-extra",
        "s1",
        T0,
        &json!({"role": "assistant", "future": 1}),
    )?;
    let part_tokens = |input: u64| json!({"input": input, "output": 2, "reasoning": 0, "cache": {"read": 0, "write": 0, "extra": 7}, "extra": 8});
    for (id, input) in [("p1", 1), ("p2", 3)] {
        put_part(
            &database,
            id,
            "legacy-part-extra",
            "s1",
            &json!({"type": "step-finish", "snapshot": "abc", "cost": 0.1, "tokens": part_tokens(input)}),
        )?;
    }
    write_json_message(&source, "sj", "json-extra", T0, None)?;
    let message = source.join("storage/message/sj/json-extra.json");
    let mut timed = envelope(extras.clone());
    timed["time"] = json!({"created": T0, "completed": T0 + 1});
    std::fs::write(&message, serde_json::to_vec(&timed)?)?;
    write_json_message(&source, "sj", "json-part-extra", T0, None)?;
    for (id, input) in [("p1", 1), ("p2", 3)] {
        write_json_part(
            &source,
            "json-part-extra",
            id,
            &json!({"type": "step-finish", "snapshot": "abc", "tokens": part_tokens(input)}),
        )?;
    }
    // Known field malformed: the string "20" is not a count, so only this record is refused.
    let mut malformed = extras.clone();
    malformed["output"] = json!("20");
    put_message(
        &database,
        "legacy-malformed",
        "s1",
        T0,
        &envelope(malformed),
    )?;

    let (records, report) = acquire_twice(&source, &data, &home)?;
    assert_eq!(report.outcome, PassOutcome::Partial, "{report:?}");
    assert_eq!(
        report.failure,
        Some(FailureCode::InvalidRecord),
        "{report:?}"
    );
    let expected_all = [Some(10), Some(20), Some(3), Some(4), Some(5), Some(42)];
    for id in ["legacy-extra", "v2-extra", "json-extra"] {
        assert_eq!(values(find(&records, id)), expected_all, "{id}");
        assert!(!find(&records, id).mirror_conflict, "{id}");
    }
    for id in ["legacy-part-extra", "json-part-extra"] {
        let record = find(&records, id);
        // Two parts: input 1 + 3, output 2 + 2, others 0; derived total 4 + 4.
        assert_eq!(
            values(record),
            [Some(4), Some(4), Some(0), Some(0), Some(0), Some(8)],
            "{id}"
        );
        assert_eq!(record.selected_part_ids, ["p1", "p2"], "{id}");
    }
    assert_eq!(records.len(), 5, "the malformed record is not published");
    assert!(
        records
            .iter()
            .all(|record| record.message_id != "legacy-malformed")
    );
    Ok(())
}

/// Look-alike files and misplaced JSON are never treated as sources: only `opencode*.db` and
/// `storage/message/<session>/<message>.json` count, and each ignored decoy would have
/// published a recognizable total or failed the pass had it been opened.
#[test]
fn lookalike_sibling_files_are_never_opened_as_sources() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let database = open_fixture(&source.join("opencode.db"))?;
    put_message(&database, "real", "s", T0, &assistant(usage(5)))?;
    for name in [
        "opencode.db.bak",
        "opencode.sqlite",
        "xopencode.db",
        "opencode",
        "opencode.dbx",
    ] {
        std::fs::write(source.join(name), b"not a database")?;
    }
    let decoy = serde_json::to_vec(&assistant(usage(55_555)))?;
    let mut decoy_json = serde_json::from_slice::<Value>(&decoy)?;
    decoy_json["time"] = json!({"created": T0});
    let decoy_json = serde_json::to_vec(&decoy_json)?;
    for path in [
        "storage/message/s/too/deep.json",
        "storage/message/s/message.txt",
        "storage/messages/s/message.json",
        "storage/other/s/message.json",
        "message/s/message.json",
        "storage/message/loose.json",
    ] {
        let path = source.join(path);
        std::fs::create_dir_all(path.parent().ok_or("parent")?)?;
        std::fs::write(path, &decoy_json)?;
    }
    write_json_message(&source, "s", "json-real", T0, Some(usage(6)))?;
    let ignored_part = source.join("storage/part/json-real/ignored.txt");
    std::fs::create_dir_all(ignored_part.parent().ok_or("parent")?)?;
    std::fs::write(
        ignored_part,
        serde_json::to_vec(&json!({"type": "step-finish", "tokens": usage(55_555)}))?,
    )?;

    let fs = RecordingFs::new();
    let observed = fs.clone();
    let mut engine = open_recording_engine(fs, &source, &data, &home)
        .map_err(|report| format!("open failed: {report:?}"))?;
    let report = engine.pass(consented(), 1);
    assert_eq!(report.outcome, PassOutcome::Consistent, "{report:?}");
    assert_eq!(
        report.counters.header_reads, 1,
        "only the real database has a header read"
    );
    assert_eq!(observed.metrics().sqlite_opens, 1);
    assert_eq!(
        winners(&engine.observations()?),
        [
            ("json-real".to_owned(), Some(6), false),
            ("real".to_owned(), Some(5), false)
        ]
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Hostile replacement at every filesystem boundary of the JSON layout.
// ---------------------------------------------------------------------------------------------

fn decoy_message() -> TestResult<Vec<u8>> {
    Ok(serde_json::to_vec(&json!({
        "role": "assistant", "time": {"created": T0},
        "tokens": counts(Some(77_777), Some(0), Some(0), Some(0), Some(0), None)
    }))?)
}

fn decoy_part() -> TestResult<Vec<u8>> {
    Ok(serde_json::to_vec(&step_finish(counts(
        Some(77_777),
        Some(0),
        Some(0),
        Some(0),
        Some(0),
        None,
    )))?)
}

/// A path swapped for a link to outside data or a FIFO exactly when the engine is about to open
/// it (message file, part file, part directory, message directory): the pass finishes inside its
/// deadline, nothing from the hostile state is published or staged, the outside decoys are
/// untouched, and putting the original back recovers the exact record.
#[test]
fn hostile_replacement_at_every_boundary_is_bounded_unpublished_and_recoverable() -> TestResult {
    let _guard = vfs_test_guard();
    let cases = [
        (
            "message file",
            OpenKind::Bounded,
            "storage/message/session-a/hostile.json",
            "hostile.json",
        ),
        (
            "part file",
            OpenKind::Bounded,
            "storage/part/hostile/p1.json",
            "p1.json",
        ),
        (
            "part directory",
            OpenKind::Directory,
            "storage/part/hostile",
            "part-dir",
        ),
        (
            "message directory",
            OpenKind::Directory,
            "storage/message/session-a",
            "message-dir",
        ),
    ];
    for (name, kind, victim_relative, decoy_name) in cases {
        for replacement in ["symlink", "fifo"] {
            let directory = tempdir()?;
            let base = directory.path().canonicalize()?;
            let (source, data, home) = source_roots(&base)?;
            write_json_message(
                &source,
                "session-a",
                "hostile",
                T0,
                Some(counts(Some(1), Some(2), Some(0), Some(0), Some(0), None)),
            )?;
            write_json_part(
                &source,
                "hostile",
                "p1",
                &step_finish(counts(Some(5), Some(6), Some(0), Some(0), Some(0), None)),
            )?;
            let outside = base.join("outside");
            std::fs::create_dir_all(outside.join("part-dir"))?;
            std::fs::create_dir_all(outside.join("message-dir"))?;
            let decoys = [
                (outside.join("hostile.json"), decoy_message()?),
                (outside.join("p1.json"), decoy_part()?),
                (outside.join("part-dir/p1.json"), decoy_part()?),
                (outside.join("message-dir/hostile.json"), decoy_message()?),
            ];
            for (path, bytes) in &decoys {
                std::fs::write(path, bytes)?;
            }
            let victim = source.join(victim_relative);
            let parked = base.join("parked");
            let target = outside.join(decoy_name);
            let fired = Arc::new(AtomicBool::new(false));
            let fs = RecordingFs::new();
            let (hook_victim, hook_parked, hook_target, hook_fired) =
                (victim.clone(), parked.clone(), target, Arc::clone(&fired));
            fs.on_boundary(move |open, path| {
                if open == kind && path == hook_victim && !hook_fired.swap(true, Ordering::SeqCst) {
                    std::fs::rename(&hook_victim, &hook_parked).expect("park victim");
                    if replacement == "symlink" {
                        std::os::unix::fs::symlink(&hook_target, &hook_victim).expect("symlink");
                    } else {
                        mkfifo(&hook_victim).expect("fifo");
                    }
                }
            });
            let engine = open_recording_engine(fs, &source, &data, &home)
                .map_err(|report| format!("{name}/{replacement}: open failed: {report:?}"))?;
            let (mut engine, report) = pass_within(engine, 1, 10)?;
            assert!(
                fired.load(Ordering::SeqCst),
                "{name}/{replacement}: race never fired"
            );
            assert_ne!(
                report.outcome,
                PassOutcome::Consistent,
                "{name}/{replacement}: {report:?}"
            );
            assert!(
                engine.observations()?.is_empty(),
                "{name}/{replacement}: hostile state published: {report:?}"
            );
            let store = history(&data)?;
            for table_probe in [
                "SELECT COUNT(*) FROM usage_events WHERE input_tokens = 77777",
                "SELECT COUNT(*) FROM reported_groups WHERE input_tokens = 77777",
                "SELECT COUNT(*) FROM opencode_candidate_spool WHERE candidate_json LIKE '%77777%'",
            ] {
                let leaked: i64 = store.query_row(table_probe, [], |row| row.get(0))?;
                assert_eq!(leaked, 0, "{name}/{replacement}: {table_probe}");
            }
            drop(store);
            for (path, bytes) in &decoys {
                assert_eq!(
                    &std::fs::read(path)?,
                    bytes,
                    "{name}/{replacement}: decoy written"
                );
            }

            std::fs::remove_file(&victim)?;
            std::fs::rename(&parked, &victim)?;
            let reports = run_until_consistent(&mut engine, 100_000, 6);
            let last = reports.last().ok_or("no recovery pass")?;
            assert_eq!(
                last.outcome,
                PassOutcome::Consistent,
                "{name}/{replacement}: {reports:?}"
            );
            let records = engine.observations()?;
            assert_eq!(records.len(), 1, "{name}/{replacement}");
            assert_eq!(
                values(&records[0]),
                [Some(5), Some(6), Some(0), Some(0), Some(0), Some(11)],
                "{name}/{replacement}"
            );
            assert_eq!(records[0].selected_part_ids, ["p1"], "{name}/{replacement}");
        }
    }
    Ok(())
}

/// The metadata spool accepts exactly 200,000 rows and exactly 64 MiB (67,108,864 bytes of path
/// plus parser kind) and refuses one byte more; a refusal leaves the durable frontier untouched.
#[test]
fn spool_ceilings_accept_the_exact_cap_and_refuse_one_byte_more() -> TestResult {
    let spool = |index: u64, path: String| quotern_core::store::SpoolFile {
        relative_path: PathBuf::from(path),
        device: 1,
        inode: index,
        size: 0,
        mtime_ns: 0,
        parser_kind: "sqlite".to_owned(),
    };
    // The frontier row "moved" (5 bytes) is part of the same cap as the metadata rows.
    // 16,384 rows of 4,090 + 6 = 4,096 bytes each; the first path gives up the frontier's bytes.
    let padded = |index: u64, length: usize| format!("{index:05}{}", "a".repeat(length - 5));
    type Case = (&'static str, Vec<quotern_core::store::SpoolFile>, bool);
    let cases: Vec<Case> = vec![
        (
            "200,000 rows including the frontier row",
            (0..199_999)
                .map(|index| spool(index, format!("f{index:06}")))
                .collect(),
            true,
        ),
        (
            "200,001 rows including the frontier row",
            (0..200_000)
                .map(|index| spool(index, format!("f{index:06}")))
                .collect(),
            false,
        ),
        (
            "67,108,864 bytes including the frontier row",
            (0..16_384)
                .map(|index| spool(index, padded(index, if index == 0 { 4_085 } else { 4_090 })))
                .collect(),
            true,
        ),
        (
            "67,108,865 bytes including the frontier row",
            (0..16_384)
                .map(|index| spool(index, padded(index, if index == 0 { 4_086 } else { 4_090 })))
                .collect(),
            false,
        ),
    ];
    // Independent physical oracle: UTF-8 octets of every text column the spool retains.
    let octets = |data: &Path| -> TestResult<(i64, i64)> {
        let connection = history(data)?;
        let rows: i64 = connection.query_row(
            "SELECT (SELECT COUNT(*) FROM metadata_spool) + (SELECT COUNT(*) FROM frontier_directories) \
             + (SELECT COUNT(*) FROM opencode_candidate_spool)",
            [],
            |row| row.get(0),
        )?;
        let bytes: i64 = connection.query_row(
            "SELECT (SELECT COALESCE(SUM(length(CAST(relative_path AS BLOB)) + length(CAST(parser_kind AS BLOB))), 0) FROM metadata_spool) \
             + (SELECT COALESCE(SUM(length(CAST(relative_path AS BLOB))), 0) FROM frontier_directories) \
             + (SELECT COALESCE(SUM(length(CAST(relative_path AS BLOB)) + length(CAST(event_key AS BLOB)) \
                  + length(CAST(fingerprint AS BLOB)) + length(CAST(candidate_json AS BLOB))), 0) FROM opencode_candidate_spool)",
            [],
            |row| row.get(0),
        )?;
        Ok((rows, bytes))
    };
    for (name, files, accepted) in cases {
        let directory = tempdir()?;
        let root = directory.path().join("root");
        std::fs::create_dir_all(&root)?;
        let data = directory.path().join("data");
        let mut store = quotern_core::store::Store::open(&data)?;
        let registration =
            store.register_source(&root, quotern_core::domain::SourceKind::Custom, (1, 1))?;
        let kept = [(root.join("kept"), 1_usize, false)];
        store.stage_scan(files_request(&registration, &root, &[], &kept))?;
        let durable =
            store.load_frontier(&registration.source_id, &root, registration.generation)?;
        let moved = [(root.join("moved"), 1_usize, false)];
        let result = store.stage_scan(files_request(&registration, &root, &files, &moved));
        let frontier =
            store.load_frontier(&registration.source_id, &root, registration.generation)?;
        if accepted {
            result.map_err(|error| format!("{name}: {error:?}"))?;
            assert_eq!(frontier.len(), 1, "{name}");
            assert_eq!(frontier[0].0, root.join("moved"), "{name}");
            let (rows, bytes) = octets(&data)?;
            assert_eq!(rows, files.len() as i64 + 1, "{name}");
            if name.contains("bytes") {
                assert_eq!(
                    bytes, 67_108_864,
                    "{name}: exactly the cap, measured in octets"
                );
            } else {
                assert_eq!(rows, 200_000, "{name}");
            }
        } else {
            assert_eq!(
                result.err(),
                Some(quotern_core::store::StoreError::LimitExceeded),
                "{name}"
            );
            assert_eq!(frontier, durable, "{name}: refusal changed the frontier");
            let rows: i64 = scalar(&data, "SELECT COUNT(*) FROM metadata_spool")?;
            assert_eq!(rows, 0, "{name}: refusal staged rows");
        }
    }

    // Multi-batch, multibyte: a later batch is charged for the octets of everything already
    // retained, not its character count. Each path is 5 digits, 2,040 two-byte characters and
    // 5 ASCII characters: 4,090 octets but only 2,050 characters.
    let multibyte = |index: u64, extra: usize| {
        format!(
            "{index:05}{}{}{}",
            "\u{e9}".repeat(2_040),
            "a".repeat(5),
            "a".repeat(extra)
        )
    };
    for (name, extra, accepted) in [("exact cap", 0_usize, true), ("one octet over", 1, false)] {
        let directory = tempdir()?;
        let root = directory.path().join("root");
        std::fs::create_dir_all(&root)?;
        let data = directory.path().join("data");
        let mut store = quotern_core::store::Store::open(&data)?;
        let registration =
            store.register_source(&root, quotern_core::domain::SourceKind::Custom, (1, 1))?;
        let first: Vec<_> = (0..8_192)
            .map(|index| spool(index, multibyte(index, 0)))
            .collect();
        let second: Vec<_> = (8_192..16_384)
            .map(|index| {
                spool(
                    index,
                    multibyte(index, if index == 16_383 { extra } else { 0 }),
                )
            })
            .collect();
        store.stage_scan(files_request(&registration, &root, &first, &[]))?;
        let result = store.stage_scan(files_request(&registration, &root, &second, &[]));
        let (_, bytes) = octets(&data)?;
        if accepted {
            result.map_err(|error| format!("{name}: {error:?}"))?;
            assert_eq!(bytes, 67_108_864, "{name}: exactly the cap in octets");
        } else {
            assert_eq!(
                result.err(),
                Some(quotern_core::store::StoreError::LimitExceeded),
                "{name}: the second batch crossed the cap in octets"
            );
            assert_eq!(
                bytes, 33_554_432,
                "{name}: only the first batch stayed durable"
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Second-fold corrections: data-root binding, effect-free store refusal, cursors, caps
// ---------------------------------------------------------------------------------------------

/// A filesystem that swaps a path at an exact point of the engine's own validation sequence: the
/// `n`-th metadata call on `watch`, i.e. in the interval between root validation and the first
/// use of the data root.
#[derive(Clone)]
struct LateSwapFs {
    watch: PathBuf,
    nth: usize,
    seen: Arc<AtomicUsize>,
    swap: Arc<dyn Fn() + Send + Sync>,
}

impl quotern_core::ingest::fs::SourceFs for LateSwapFs {
    fn canonicalize(
        &self,
        path: &Path,
        counters: &mut quotern_core::domain::PassCounters,
    ) -> std::io::Result<PathBuf> {
        quotern_core::ingest::fs::RealSourceFs.canonicalize(path, counters)
    }

    fn metadata(
        &self,
        path: &Path,
        counters: &mut quotern_core::domain::PassCounters,
    ) -> std::io::Result<std::fs::Metadata> {
        if path == self.watch && self.seen.fetch_add(1, Ordering::SeqCst) + 1 == self.nth {
            (self.swap)();
        }
        quotern_core::ingest::fs::RealSourceFs.metadata(path, counters)
    }

    fn read_dir(
        &self,
        path: &Path,
        counters: &mut quotern_core::domain::PassCounters,
    ) -> std::io::Result<quotern_core::ingest::fs::DirEntries> {
        quotern_core::ingest::fs::RealSourceFs.read_dir(path, counters)
    }

    fn read_header(
        &self,
        path: &Path,
        counters: &mut quotern_core::domain::PassCounters,
    ) -> std::io::Result<Vec<u8>> {
        quotern_core::ingest::fs::RealSourceFs.read_header(path, counters)
    }

    fn read_bounded(
        &self,
        path: &Path,
        max_bytes: usize,
        counters: &mut quotern_core::domain::PassCounters,
    ) -> std::io::Result<quotern_core::ingest::fs::BoundedRead> {
        quotern_core::ingest::fs::RealSourceFs.read_bounded(path, max_bytes, counters)
    }

    fn open_sqlite(
        &self,
        path: &Path,
    ) -> Result<Connection, quotern_core::ingest::sqlite_ro::OpenError> {
        quotern_core::ingest::fs::RealSourceFs.open_sqlite(path)
    }
}

#[test]
fn data_root_swapped_after_validation_creates_no_source_file() -> TestResult {
    use std::os::unix::fs::symlink;
    let _guard = vfs_test_guard();
    // (existing data root, or a future one below an existing parent; swapped for a link into the
    // source, or for a different real directory)
    for (existing, replacement) in [
        (true, "link"),
        (false, "link"),
        (true, "directory"),
        (false, "directory"),
    ] {
        let directory = tempdir()?;
        let base = directory.path().canonicalize()?;
        let (source, _data, home) = source_roots(&base)?;
        write_json_message(
            &source,
            "s",
            "m",
            T0,
            Some(counts(Some(1), None, None, None, None, None)),
        )?;
        let anchor = base.join("anchor");
        std::fs::create_dir(&anchor)?;
        let data = if existing {
            let data = anchor.join("data");
            std::fs::create_dir(&data)?;
            data
        } else {
            anchor.join("inner").join("data")
        };
        let swapped = if existing {
            data.clone()
        } else {
            anchor.clone()
        };
        let parked = base.join("parked");
        let (swap_target, link_to) = (swapped.clone(), source.clone());
        let swap = move || {
            std::fs::rename(&swap_target, &parked).expect("park the validated directory");
            if replacement == "link" {
                symlink(&link_to, &swap_target).expect("redirect into the source");
            } else {
                std::fs::create_dir(&swap_target).expect("replace with another directory");
            }
        };
        let before = file_tree_image(&source)?;
        let fs = LateSwapFs {
            watch: source.clone(),
            nth: 2,
            seen: Arc::new(AtomicUsize::new(0)),
            swap: Arc::new(swap),
        };
        let opened = quotern_core::ingest::OpenCodeEngine::open(
            fs,
            &source,
            &data,
            &home,
            quotern_core::domain::SourceAuthorization {
                selected: true,
                consent: quotern_core::domain::ConsentState::Enabled,
            },
            quotern_core::domain::SourceKind::Custom,
        );
        let label = format!("existing={existing} replacement={replacement}");
        let report = opened
            .err()
            .ok_or_else(|| format!("{label}: the swapped root was accepted"))?;
        assert_eq!(
            report.failure,
            Some(FailureCode::Store),
            "{label}: {report:?}"
        );
        assert_eq!(
            file_tree_image(&source)?,
            before,
            "{label}: the source was written"
        );
        assert!(!source.join("history.sqlite").exists(), "{label}");
        assert!(
            !source.join("inner").exists(),
            "{label}: a directory was created in the source"
        );
        // Restoring the validated directory makes the same request succeed.
        std::fs::remove_dir_all(&swapped).or_else(|_| std::fs::remove_file(&swapped))?;
        std::fs::rename(base.join("parked"), &swapped)?;
        let engine = open_engine(&source, &data, &home)?;
        drop(engine);
        assert!(data.join("history.sqlite").exists(), "{label}: control");
    }
    Ok(())
}

/// Bytes, mode, size and mtime of every file below `root`, to prove a refusal changed nothing.
type StoredFile = (PathBuf, Vec<u8>, u32, u64, i64);

fn store_image(root: &Path) -> TestResult<Vec<StoredFile>> {
    let mut image = Vec::new();
    for (path, bytes) in file_tree_image(root)? {
        let metadata = std::fs::metadata(root.join(&path))?;
        image.push((
            path,
            bytes,
            metadata.mode() & 0o7777,
            metadata.len(),
            metadata.mtime_nsec(),
        ));
    }
    Ok(image)
}

#[test]
fn incompatible_application_stores_are_refused_with_every_byte_untouched() -> TestResult {
    use quotern_core::store::{Store, StoreError};
    // A foreign database that merely has the right header, a previously generated unshipped-v1
    // shape that lacks the amended columns, and a newer version committed only in the WAL.
    type Prepare = fn(&Path) -> TestResult;
    let cases: [(&str, StoreError, Prepare); 5] = [
        ("foreign-v0", StoreError::Corrupt, |path| {
            let c = Connection::open(path.join("history.sqlite"))?;
            c.execute_batch("CREATE TABLE sources(id TEXT); INSERT INTO sources VALUES ('x');")?;
            Ok(())
        }),
        (
            "unshipped-v1-without-amended-columns",
            StoreError::Corrupt,
            |path| {
                drop(Store::open(path)?);
                let c = Connection::open(path.join("history.sqlite"))?;
                let _: String = c.query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))?;
                c.execute_batch("ALTER TABLE sources DROP COLUMN known_clock;")?;
                Ok(())
            },
        ),
        (
            "newer-version-only-in-the-wal",
            StoreError::UnsupportedVersion,
            |path| {
                drop(Store::open(path)?);
                // Keep a WAL connection open so the committed version stays in the log, and copy the
                // database and log (no shared-memory file) into the directory under test.
                let scratch = path.join("scratch");
                std::fs::create_dir(&scratch)?;
                std::fs::copy(path.join("history.sqlite"), scratch.join("history.sqlite"))?;
                let live = Connection::open(scratch.join("history.sqlite"))?;
                let _: i64 = live.query_row("PRAGMA wal_autocheckpoint=0", [], |row| row.get(0))?;
                live.execute_batch("PRAGMA user_version = 99;")?;
                assert!(
                    scratch.join("history.sqlite-wal").exists(),
                    "the version lives only in the log"
                );
                std::fs::copy(
                    scratch.join("history.sqlite-wal"),
                    path.join("history.sqlite-wal"),
                )?;
                drop(live);
                std::fs::remove_dir_all(&scratch)?;
                Ok(())
            },
        ),
        (
            "incompatible-schema-only-in-the-wal",
            StoreError::Corrupt,
            |path| {
                drop(Store::open(path)?);
                let scratch = path.join("scratch");
                std::fs::create_dir(&scratch)?;
                std::fs::copy(path.join("history.sqlite"), scratch.join("history.sqlite"))?;
                let live = Connection::open(scratch.join("history.sqlite"))?;
                let _: i64 = live.query_row("PRAGMA wal_autocheckpoint=0", [], |row| row.get(0))?;
                // The incompatible shape (a dropped amended column) is committed only in the log.
                live.execute_batch("ALTER TABLE sources DROP COLUMN known_clock;")?;
                assert!(scratch.join("history.sqlite-wal").exists());
                std::fs::copy(
                    scratch.join("history.sqlite-wal"),
                    path.join("history.sqlite-wal"),
                )?;
                drop(live);
                std::fs::remove_dir_all(&scratch)?;
                Ok(())
            },
        ),
        ("hot-rollback-journal", StoreError::Corrupt, |path| {
            let c = Connection::open(path.join("history.sqlite"))?;
            c.execute_batch("CREATE TABLE sources(id TEXT); INSERT INTO sources VALUES ('x');")?;
            drop(c);
            std::fs::write(path.join("history.sqlite-journal"), [0xd9_u8; 512])?;
            Ok(())
        }),
    ];
    for (name, expected, prepare) in cases {
        let directory = tempdir()?;
        let data = directory.path().join("data");
        std::fs::create_dir(&data)?;
        prepare(&data)?;
        let before = store_image(&data)?;
        let result = Store::open(&data);
        assert_eq!(result.err(), Some(expected), "{name}");
        assert_eq!(
            store_image(&data)?,
            before,
            "{name}: bytes, inventory, mode, size and mtime stay exactly as they were"
        );
    }
    // Controls: a fresh store and a cleanly closed current store open and reopen.
    let directory = tempdir()?;
    let data = directory.path().join("data");
    drop(Store::open(&data)?);
    drop(Store::open(&data)?);
    Ok(())
}

#[test]
fn the_minimum_rowid_is_reachable_in_every_layout_initially_and_after_reopen() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let c = open_fixture(&source.join("opencode.db"))?;
    let usage = |input: u64| json!({"role": "assistant", "tokens": counts(Some(input), Some(0), Some(0), Some(0), Some(0), None)});
    for (rowid, id, input) in [
        (i64::MIN, "legacy-min", 11_u64),
        (i64::MIN + 1, "legacy-next", 22),
    ] {
        c.execute(
            "INSERT INTO message(rowid, id, session_id, time_created, data) VALUES (?1, ?2, 's', ?3, ?4)",
            rusqlite::params![rowid, id, T0, serde_json::to_vec(&usage(input))?],
        )?;
    }
    c.execute("INSERT INTO session_v2(id) VALUES ('v2s')", [])?;
    for (rowid, id, input) in [(i64::MIN, "v2-min", 33_u64), (i64::MIN + 1, "v2-next", 44)] {
        c.execute(
            "INSERT INTO session_message(rowid, id, session_id, type, seq, time_created, data) \
             VALUES (?1, ?2, 'v2s', 'assistant', 1, ?3, ?4)",
            rusqlite::params![rowid, id, T0, serde_json::to_vec(&usage(input))?],
        )?;
    }
    drop(c);
    let mut engine = open_engine(&source, &data, &home)?;
    let first = engine.pass(consented(), 1);
    assert_eq!(first.outcome, PassOutcome::Consistent, "{first:?}");
    let seen = |engine: &quotern_core::ingest::OpenCodeEngine<_>| -> TestResult<Vec<(String, Option<u64>, u64)>> {
        let mut seen: Vec<_> = engine
            .observations()?
            .into_iter()
            .map(|record| (record.message_id, record.input.value, record.revision))
            .collect();
        seen.sort();
        Ok(seen)
    };
    let expected = vec![
        ("legacy-min".to_owned(), Some(11), 1),
        ("legacy-next".to_owned(), Some(22), 1),
        ("v2-min".to_owned(), Some(33), 1),
        ("v2-next".to_owned(), Some(44), 1),
    ];
    assert_eq!(seen(&engine)?, expected, "each boundary row exactly once");
    // A fresh engine on the same store reads every row again without duplicating or revising.
    drop(engine);
    let mut engine = open_engine(&source, &data, &home)?;
    let again = engine.pass(consented(), 2);
    assert_eq!(again.outcome, PassOutcome::Consistent, "{again:?}");
    assert_eq!(seen(&engine)?, expected);
    // The cursor of a capped read stays exact at the boundary: rowid MIN is a value, not "none".
    let cursor: Option<String> = history(&data)?
        .query_row(
            "SELECT working_cursor_key FROM opencode_progress",
            [],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    assert_eq!(
        cursor, None,
        "a finished generation keeps no acquisition cursor"
    );
    Ok(())
}

/// Part rows ordered so the step-finish parts sort after any amount of raw non-usage parts.
fn text_part(c: &Connection, index: u32, message: &str) -> TestResult {
    put_part(
        c,
        &format!("a-{index:05}"),
        message,
        "s",
        &json!({"type": "text", "text": "x"}),
    )
}

#[test]
fn raw_non_usage_parts_resume_across_passes_and_do_not_hit_the_selected_part_cap() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let c = open_fixture(&source.join("opencode.db"))?;
    put_message(&c, "big", "s", T0, &json!({"role": "assistant"}))?;
    let tx = c.unchecked_transaction()?;
    // 3,000 raw parts cost 6,000 emitted rows (list + payload): more than one pass may emit.
    for index in 0..3_000 {
        text_part(&tx, index, "big")?;
    }
    tx.commit()?;
    put_part(
        &c,
        "z-1",
        "big",
        "s",
        &step_finish(counts(Some(40), Some(0), Some(0), Some(0), Some(0), None)),
    )?;
    put_part(
        &c,
        "z-2",
        "big",
        "s",
        &step_finish(counts(Some(60), Some(0), Some(0), Some(0), Some(0), None)),
    )?;
    drop(c);
    let mut engine = open_engine(&source, &data, &home)?;
    let first = engine.pass(consented(), 1);
    assert_eq!(first.outcome, PassOutcome::CatchingUp, "{first:?}");
    assert!(first.counters.rows_read <= 5_000, "{first:?}");
    assert!(
        engine.observations()?.is_empty(),
        "a half-read group is never published"
    );
    let cursor: String = scalar(&data, "SELECT working_cursor_key FROM opencode_progress")?;
    let cursor: Value = serde_json::from_str(&cursor)?;
    assert!(
        cursor["legacy"]["group"]["after_part"].is_string(),
        "suspended mid-group: {cursor}"
    );
    assert!(
        cursor["legacy"]["group"]["parts"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "{cursor}"
    );
    // A restart resumes the same group from the durable cursor.
    drop(engine);
    let mut engine = open_engine(&source, &data, &home)?;
    let reports = run_until_consistent(&mut engine, 10, 6);
    let last = reports.last().ok_or("pass")?;
    assert_eq!(last.outcome, PassOutcome::Consistent, "{reports:?}");
    let records = engine.observations()?;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].input.value, Some(100));
    assert_eq!(records[0].selected_part_ids, ["z-1", "z-2"]);
    assert_eq!(records[0].revision, 1);
    Ok(())
}

#[test]
fn rejected_rows_neither_copy_their_payload_nor_charge_bytes() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let c = open_fixture(&source.join("opencode.db"))?;
    let payload = vec![b' '; 262_144];
    let tx = c.unchecked_transaction()?;
    for index in 0..500 {
        // The identity column is over its byte limit, so the row is rejected before its payload.
        tx.execute(
            "INSERT INTO message(id, session_id, time_created, data) VALUES (?1, 's', ?2, ?3)",
            rusqlite::params![format!("{index:04}{}", "i".repeat(300)), T0, payload],
        )?;
    }
    tx.commit()?;
    // The query itself withholds the payload column: SQLite never hands the bytes out.
    let sql = quotern_core::adapters::opencode::message_query(
        false,
        quotern_core::adapters::opencode::Lower::Start,
    );
    let mut statement = c.prepare(&sql)?;
    let mut rows = statement.query(rusqlite::params![
        256_i64,
        262_144_i64,
        1_000_i64,
        32_i64,
        67_108_864_i64
    ])?;
    let mut withheld = 0;
    while let Some(row) = rows.next()? {
        assert_eq!(
            row.get::<_, Option<Vec<u8>>>(10)?,
            None,
            "payload column of an invalid row"
        );
        assert_eq!(
            row.get::<_, Option<i64>>(9)?,
            Some(262_144),
            "its size is still reported"
        );
        withheld += 1;
    }
    assert_eq!(withheld, 500);
    drop(rows);
    drop(statement);
    let copied: i64 = c.query_row(
        "SELECT COUNT(*) FROM message WHERE NOT (octet_length(id) <= 256) AND octet_length(data) = 262144",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(
        copied, 500,
        "the fixture really holds 500 cap-sized payloads behind invalid ids"
    );
    drop(c);
    let mut engine = open_engine(&source, &data, &home)?;
    let report = engine.pass(consented(), 1);
    assert_eq!(
        u64::from(report.counters.rows_read),
        500 + admission_rows(&source.join("opencode.db"))?,
        "{report:?}"
    );
    assert_eq!(report.counters.rejected_records, 500, "{report:?}");
    assert_eq!(
        report.counters.bytes_read, 0,
        "no rejected payload is fetched, so none is charged either: {report:?}"
    );
    assert_eq!(engine.snapshot(&report)?.projection.records, 0);
    Ok(())
}

#[test]
fn mixed_totals_keep_derivation_and_acquisition_label_through_reopen_and_the_encoded_consumer()
-> TestResult {
    use quotern_core::domain::{AcquisitionConsistency, ProjectionConsistency};
    use quotern_core::snapshot::{ObservationPage, SourceSnapshot};
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let c = open_fixture(&source.join("opencode.db"))?;
    // p1 reports 99 although its components sum to 42; p2 has no total but all five components.
    put_message(&c, "mix", "s", T0, &json!({"role": "assistant"}))?;
    put_part(
        &c,
        "p1",
        "mix",
        "s",
        &step_finish(counts(
            Some(10),
            Some(10),
            Some(10),
            Some(10),
            Some(2),
            Some(99),
        )),
    )?;
    put_part(
        &c,
        "p2",
        "mix",
        "s",
        &step_finish(counts(Some(1), Some(0), Some(0), Some(0), Some(0), None)),
    )?;
    // A JSON message with an explicit zero total, read file by file.
    write_json_message(
        &source,
        "sj",
        "jmsg",
        T0 + 1,
        Some(counts(Some(0), Some(0), Some(0), Some(0), Some(0), Some(0))),
    )?;
    drop(c);
    let mut engine = open_engine(&source, &data, &home)?;
    let report = run_until_consistent(&mut engine, 1, 6)
        .pop()
        .ok_or("pass")?;
    assert_eq!(report.outcome, PassOutcome::Consistent, "{report:?}");
    let check =
        |engine: &quotern_core::ingest::OpenCodeEngine<_>, report: &PassReport| -> TestResult {
            let records = engine.observations()?;
            let mix = find(&records, "mix");
            assert_eq!(mix.total.value, Some(100), "99 explicit + 1 derived");
            assert_eq!(mix.total.provenance, Some(Provenance::Derived));
            assert_eq!(
                mix.source_convention.as_deref(),
                Some("codexbar-3239175f-disjoint")
            );
            assert!(mix.total_mismatch, "100 against components summing to 43");
            assert_eq!(
                mix.acquisition_consistency,
                AcquisitionConsistency::SqliteReadTransaction
            );
            let json = find(&records, "jmsg");
            assert_eq!(json.total.value, Some(0), "explicit zero is a value");
            assert_eq!(json.total.provenance, Some(Provenance::Reported));
            assert_eq!(json.source_convention, None);
            assert_eq!(
                json.acquisition_consistency,
                AcquisitionConsistency::FileByFileBestEffort
            );
            let projection = engine.snapshot(report)?.projection;
            assert_eq!(
                projection.acquisition_consistency,
                Some(ProjectionConsistency::Mixed)
            );
            assert_eq!(projection.total.value, Some(100));
            assert_eq!(projection.total.provenance, Some(Provenance::Derived));
            assert_eq!(
                projection.source_convention.as_deref(),
                Some("codexbar-3239175f-disjoint")
            );
            // The serialized envelope round-trips through the validated decoder with exact values.
            let encoded = serde_json::to_vec(&engine.snapshot(report)?)?;
            assert_eq!(SourceSnapshot::decode(&encoded)?.projection, projection);
            let page = engine.observations_page(None, 10)?;
            let decoded = ObservationPage::decode(&serde_json::to_vec(&page)?)?;
            assert_eq!(decoded, page);
            Ok(())
        };
    check(&engine, &report)?;
    let persisted: (Option<String>, Option<String>, String) = history(&data)?.query_row(
        "SELECT total_provenance, source_convention, acquisition_consistency FROM usage_events WHERE message_id = 'mix'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(
        persisted,
        (
            Some("derived".to_owned()),
            Some("codexbar-3239175f-disjoint".to_owned()),
            "sqlite_read_transaction".to_owned()
        )
    );
    drop(engine);
    let mut engine = open_engine(&source, &data, &home)?;
    let report = engine.pass(consented(), 100);
    check(&engine, &report)?;

    // The decoder refuses relational contradictions the derive alone would accept.
    let good = serde_json::to_value(engine.snapshot(&report)?)?;
    type Contradiction = (&'static str, fn(&mut Value));
    let contradictions: [Contradiction; 4] = [
        ("convention on a reported total", |v| {
            v["projection"]["total"]["provenance"] = json!("reported");
        }),
        ("null total with a current status", |v| {
            v["projection"]["total"]["value"] = Value::Null;
        }),
        ("records without a consistency", |v| {
            v["projection"]["acquisition_consistency"] = Value::Null;
        }),
        ("derived component", |v| {
            v["projection"]["input"]["provenance"] = json!("derived");
        }),
    ];
    for (name, mutate) in contradictions {
        let mut value = good.clone();
        mutate(&mut value);
        assert!(
            SourceSnapshot::decode(&serde_json::to_vec(&value)?).is_err(),
            "{name} must be rejected by the decoder"
        );
    }
    let mut empty = good.clone();
    empty["projection"]["records"] = json!(0);
    assert!(
        SourceSnapshot::decode(&serde_json::to_vec(&empty)?).is_err(),
        "records 0 with a consistency"
    );
    Ok(())
}

#[test]
fn reconciliation_is_dirty_from_the_first_incomplete_pass_until_a_clean_completion() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let c = open_fixture(&source.join("opencode.db"))?;
    put_message(&c, "g", "s", T0, &json!({"role": "assistant"}))?;
    put_part(
        &c,
        "p1",
        "g",
        "s",
        &step_finish(counts(Some(40), Some(0), Some(0), Some(0), Some(0), None)),
    )?;
    put_part(
        &c,
        "p2",
        "g",
        "s",
        &step_finish(counts(Some(60), Some(0), Some(0), Some(0), Some(0), None)),
    )?;
    let mut engine = open_engine(&source, &data, &home)?;
    let dirty = |data: &Path| scalar::<i64>(data, "SELECT dirty FROM sources");
    assert_eq!(dirty(&data)?, 0, "nothing read yet");
    let clean = engine.pass(consented(), 1);
    assert_eq!(clean.outcome, PassOutcome::Consistent, "{clean:?}");
    assert_eq!(dirty(&data)?, 0, "a clean terminal completion clears it");
    // An unfinished catch-up generation is dirty and keeps its last good.
    let bulk = c.unchecked_transaction()?;
    for index in 0..5_100_i64 {
        bulk.execute(
            "INSERT INTO message(id, session_id, time_created, data) VALUES (?1, 's', ?2, ?3)",
            rusqlite::params![format!("bulk-{index:05}"), T0 + index, serde_json::to_vec(&json!({"role": "assistant", "tokens": counts(Some(1), None, None, None, None, None)}))?],
        )?;
    }
    bulk.commit()?;
    // The prune lands before the catch-up generation reads the group: its final outcome is partial.
    c.execute("DELETE FROM part WHERE id = 'p2'", [])?;
    let catching = engine.pass(consented(), 2);
    assert_eq!(catching.outcome, PassOutcome::CatchingUp, "{catching:?}");
    assert_eq!(
        dirty(&data)?,
        1,
        "the open generation is reconciliation in progress"
    );
    assert!(engine.snapshot(&catching)?.projection.records >= 1);
    // The pruned group makes the final generation partial: the pending group stays dirty.
    let mut last = catching;
    for step in 0..8 {
        last = engine.pass(consented(), 3 + step * 60_000);
        if last.outcome != PassOutcome::CatchingUp {
            break;
        }
        assert_eq!(dirty(&data)?, 1, "still catching up");
    }
    assert_eq!(last.outcome, PassOutcome::Partial, "{last:?}");
    assert_eq!(dirty(&data)?, 1, "a pending group is never called clean");
    assert_eq!(
        find(&engine.observations_page(None, 1_000)?.observations, "g")
            .input
            .value,
        Some(100)
    );
    Ok(())
}

#[test]
fn an_oversized_or_malformed_json_parent_marks_the_retained_group_pending_with_its_reason()
-> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    write_json_message(
        &source,
        "sj",
        "m",
        T0,
        Some(counts(Some(1), None, None, None, None, None)),
    )?;
    write_json_part(
        &source,
        "m",
        "p1",
        &step_finish(counts(Some(100), Some(0), Some(0), Some(0), Some(0), None)),
    )?;
    let mut engine = open_engine(&source, &data, &home)?;
    let first = run_until_consistent(&mut engine, 1, 5)
        .pop()
        .ok_or("pass")?;
    assert_eq!(first.outcome, PassOutcome::Consistent, "{first:?}");
    let state = |engine: &quotern_core::ingest::OpenCodeEngine<_>| -> TestResult<(Option<u64>, bool, Option<FailureCode>, u64)> {
        let records = engine.observations()?;
        let record = find(&records, "m");
        Ok((record.input.value, record.pending_partial, record.pending_reason, record.revision))
    };
    assert_eq!(state(&engine)?, (Some(100), false, None, 1));
    let parent = source.join("storage/message/sj/m.json");
    // Parent enlarged beyond 256 KiB: last complete group retained and flagged.
    std::fs::write(&parent, vec![b' '; 256 * 1024 + 1])?;
    for (index, (bytes, reason)) in [
        (None, FailureCode::RecordTooLarge),
        (Some(b"{ not json".to_vec()), FailureCode::InvalidRecord),
    ]
    .into_iter()
    .enumerate()
    {
        if let Some(bytes) = bytes {
            std::fs::write(&parent, bytes)?;
        }
        engine.pass(consented(), 100 + index as i64 * 60_000);
        assert_eq!(
            state(&engine)?,
            (Some(100), true, Some(reason), 1),
            "{reason:?}"
        );
    }
    // A stable correction replaces the value and clears the pending flag, durably.
    std::fs::write(
        &parent,
        serde_json::to_vec(
            &json!({"role": "assistant", "time": {"created": T0}, "tokens": counts(Some(1), None, None, None, None, None)}),
        )?,
    )?;
    write_json_part(
        &source,
        "m",
        "p1",
        &step_finish(counts(Some(40), Some(0), Some(0), Some(0), Some(0), None)),
    )?;
    let reports = run_until_consistent(&mut engine, 1_000_000, 6);
    assert_eq!(
        reports.last().ok_or("pass")?.outcome,
        PassOutcome::Consistent,
        "{reports:?}"
    );
    assert_eq!(state(&engine)?, (Some(40), false, None, 2));
    drop(engine);
    let mut engine = open_engine(&source, &data, &home)?;
    engine.pass(consented(), 9_000_000);
    assert_eq!(
        state(&engine)?,
        (Some(40), false, None, 2),
        "reopen: cleared once, no new revision"
    );
    Ok(())
}

#[test]
fn a_commit_during_the_production_read_transaction_stays_out_of_its_numbers_and_counts_once_next_pass()
-> TestResult {
    use std::cell::RefCell;
    use std::rc::Rc;
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let database = source.join("opencode.db");
    let holder = Rc::new(RefCell::new(live_fixture(&database)?));
    let before = source_image(&database)?;
    let mut engine = open_engine(&source, &data, &home)?;
    let derived = |input: u64| {
        support::sql_blob(&serde_json::to_vec(&json!({"role": "assistant", "tokens": counts(Some(input), Some(20), Some(3), Some(4), Some(5), None)})).expect("payload"))
    };
    let later = support::sql_blob(&serde_json::to_vec(
        &json!({"role": "assistant", "tokens": counts(Some(7), Some(0), Some(0), Some(0), Some(0), None)}),
    )?);
    let sql = format!(
        "UPDATE message SET data = {} WHERE id = 'legacy-derived'; \
         INSERT INTO message(id, session_id, time_created, data) VALUES ('later', 'session-a', 1700000009000, {later});",
        derived(11)
    );
    let writer = Rc::clone(&holder);
    // Runs inside the adapter's own read transaction, right after its first decoded group.
    quotern_core::adapters::opencode::set_transaction_hook(Some(Box::new(move || {
        writer
            .borrow_mut()
            .exec(&sql)
            .expect("the child writer commits during the read");
    })));
    let first = engine.pass(consented(), 1);
    assert_eq!(first.outcome, PassOutcome::Consistent, "{first:?}");
    let snapshot = engine.observations()?;
    assert_eq!(
        snapshot.len(),
        6,
        "the old snapshot: nothing inserted mid-read"
    );
    assert_eq!(
        find(&snapshot, "legacy-derived").input.value,
        Some(10),
        "nor updated mid-read"
    );
    assert!(snapshot.iter().all(|record| record.message_id != "later"));
    let second = engine.pass(consented(), 2);
    assert_eq!(second.outcome, PassOutcome::Consistent, "{second:?}");
    let records = engine.observations()?;
    assert_eq!(records.len(), 7);
    assert_eq!(
        records
            .iter()
            .filter(|record| record.message_id == "later")
            .count(),
        1
    );
    assert_eq!(find(&records, "later").input.value, Some(7));
    let updated = find(&records, "legacy-derived");
    assert_eq!(
        (updated.input.value, updated.total.value, updated.revision),
        (Some(11), Some(43), 2)
    );
    assert_eq!(find(&records, "later").revision, 1);
    let projection = engine.snapshot(&second)?.projection;
    assert_eq!(projection.records, 7);
    assert_eq!(projection.input.value, Some(11 + 10 + 30 + 100 + 1 + 2 + 7));
    holder.borrow_mut().stop()?;
    // Effective-effect backstop: the source files only grew through the writer, never through us.
    let after = source_image(&database)?;
    assert_eq!(before.len(), after.len());
    assert_vfs_no_mutations()?;
    Ok(())
}

/// `opencode-a.db` is known from a first complete generation, so the reserved lane reads it first
/// in every later generation; `opencode-b.db` is larger than one pass and keeps that generation
/// open after a is finished.
fn known_a_then_large_b(
    source: &Path,
    engine_data: (&Path, &Path),
) -> TestResult<(
    quotern_core::ingest::OpenCodeEngine<quotern_core::ingest::fs::RealSourceFs>,
    Connection,
)> {
    let a = open_fixture(&source.join("opencode-a.db"))?;
    put_message(
        &a,
        "a",
        "s",
        T0,
        &json!({"role": "assistant", "tokens": counts(Some(40), Some(0), Some(0), Some(0), Some(0), None)}),
    )?;
    drop(a);
    let mut engine = open_engine(source, engine_data.0, engine_data.1)?;
    let base = engine.pass(consented(), 1);
    assert_eq!(base.outcome, PassOutcome::Consistent, "{base:?}");
    let b = bulk_legacy(&source.join("opencode-b.db"), 5_100, 1)?;
    let open_generation = engine.pass(consented(), 2);
    assert_eq!(
        open_generation.outcome,
        PassOutcome::CatchingUp,
        "{open_generation:?}"
    );
    assert!(
        scalar::<i64>(
            engine_data.0,
            "SELECT COUNT(*) FROM opencode_candidate_spool"
        )? > 0,
        "the generation is open"
    );
    Ok((engine, b))
}

fn input_of(
    engine: &quotern_core::ingest::OpenCodeEngine<quotern_core::ingest::fs::RealSourceFs>,
    id: &str,
) -> TestResult<Option<u64>> {
    Ok(
        find(&engine.observations_page(None, 1_000)?.observations, id)
            .input
            .value,
    )
}

fn set_a(source: &Path, input: u64) -> TestResult {
    let a = Connection::open(source.join("opencode-a.db"))?;
    a.execute("UPDATE message SET data = ?1 WHERE id = 'a'", [serde_json::to_vec(&json!({"role": "assistant", "tokens": counts(Some(input), Some(0), Some(0), Some(0), Some(0), None)}))?])?;
    Ok(())
}

#[test]
fn a_failed_finalization_never_certifies_acquisition_evidence_older_than_the_source() -> TestResult
{
    let _guard = vfs_test_guard();
    for reopen in [false, true] {
        let directory = tempdir()?;
        let (source, data, home) = source_roots(directory.path())?;
        let (mut engine, _b) = known_a_then_large_b(&source, (&data, &home))?;
        // The pass that would finalize fails before its commit.
        engine.inject_commit_fault(quotern_core::store::FaultPoint::BeforeCommit);
        let failed = engine.pass(consented(), 3);
        assert_eq!(failed.failure, Some(FailureCode::Store), "{failed:?}");
        assert_eq!(
            scalar::<i64>(&data, "SELECT COUNT(*) FROM opencode_progress")?,
            0,
            "evidence invalidated"
        );
        // The finished database is edited in place afterwards: same inode, new value.
        set_a(&source, 41)?;
        if reopen {
            drop(engine);
            engine = open_engine(&source, &data, &home)?;
        }
        let mut now = 100_000_i64;
        let mut last = failed;
        for _ in 0..12 {
            last = engine.pass(consented(), now);
            now += 300_000;
            if last.outcome == PassOutcome::Consistent {
                break;
            }
        }
        assert_eq!(last.outcome, PassOutcome::Consistent, "{last:?}");
        assert_eq!(
            input_of(&engine, "a")?,
            Some(41),
            "the physical source was read again (reopen={reopen})"
        );
    }
    Ok(())
}

#[test]
fn a_database_replaced_after_it_finished_is_caught_before_the_generation_completes() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let (mut engine, _b) = known_a_then_large_b(&source, (&data, &home))?;
    // Replace the finished database by another inode holding a new value.
    std::fs::remove_file(source.join("opencode-a.db"))?;
    let a = open_fixture(&source.join("opencode-a.db"))?;
    put_message(
        &a,
        "a",
        "s",
        T0,
        &json!({"role": "assistant", "tokens": counts(Some(41), Some(0), Some(0), Some(0), Some(0), None)}),
    )?;
    drop(a);
    let mut now = 10_000_i64;
    let mut last = engine.pass(consented(), now);
    let mut stale_certified =
        last.outcome == PassOutcome::Consistent && input_of(&engine, "a")? == Some(40);
    for _ in 0..12 {
        if last.outcome == PassOutcome::Consistent {
            break;
        }
        now += 300_000;
        last = engine.pass(consented(), now);
        stale_certified |=
            last.outcome == PassOutcome::Consistent && input_of(&engine, "a")? == Some(40);
    }
    assert!(
        !stale_certified,
        "stale value 40 was certified as Consistent"
    );
    assert_eq!(last.outcome, PassOutcome::Consistent, "{last:?}");
    assert_eq!(input_of(&engine, "a")?, Some(41));
    Ok(())
}

#[test]
fn competing_acquisitions_inside_one_generation_restore_the_pre_generation_baseline() -> TestResult
{
    let _guard = vfs_test_guard();
    // Either arrival order of the two competing values keeps the last good value 40.
    for (first_value, second_value) in [(41_u64, 42_u64), (42, 41)] {
        let directory = tempdir()?;
        let (source, data, home) = source_roots(directory.path())?;
        write_json_message(
            &source,
            "sj",
            "m",
            T0,
            Some(counts(Some(40), None, None, None, None, None)),
        )?;
        let mut engine = open_engine(&source, &data, &home)?;
        let base = engine.pass(consented(), 1);
        assert_eq!(base.outcome, PassOutcome::Consistent, "{base:?}");
        assert_eq!(input_of(&engine, "m")?, Some(40));
        // A capped second generation: the bulk database keeps it open.
        let _bulk = bulk_legacy(&source.join("opencode.db"), 5_100, 1)?;
        write_json_message(
            &source,
            "sj",
            "m",
            T0,
            Some(counts(Some(first_value), None, None, None, None, None)),
        )?;
        let staged = engine.pass(consented(), 2);
        assert_eq!(staged.outcome, PassOutcome::CatchingUp, "{staged:?}");
        assert_eq!(
            input_of(&engine, "m")?,
            Some(first_value),
            "allowed progress: the completed group is published"
        );
        write_json_message(
            &source,
            "sj",
            "m",
            T0,
            Some(counts(Some(second_value), None, None, None, None, None)),
        )?;
        let conflict = engine.pass(consented(), 3);
        assert_eq!(
            conflict.failure,
            Some(FailureCode::SourceChanging),
            "{conflict:?}"
        );
        let records = engine.observations_page(None, 1_000)?.observations;
        let m = find(&records, "m");
        assert_eq!(
            m.input.value,
            Some(40),
            "last good, not the already staged {first_value}"
        );
        assert!(m.pending_partial);
        assert_eq!(m.pending_reason, Some(FailureCode::SourceChanging));
        assert_eq!(scalar::<i64>(&data, "SELECT dirty FROM sources")?, 1);
        // Once the source holds still, one stable generation publishes the final value.
        let mut now = 1_000_000_i64;
        let mut last = conflict;
        for _ in 0..16 {
            last = engine.pass(consented(), now);
            now += 400_000;
            if last.outcome == PassOutcome::Consistent {
                break;
            }
        }
        assert_eq!(last.outcome, PassOutcome::Consistent, "{last:?}");
        let records = engine.observations_page(None, 1_000)?.observations;
        let m = find(&records, "m");
        assert_eq!(
            (m.input.value, m.pending_partial),
            (Some(second_value), false)
        );
        assert_eq!(scalar::<i64>(&data, "SELECT dirty FROM sources")?, 0);
    }
    Ok(())
}

type GroupState = (Option<u64>, u64, bool, Option<FailureCode>, Vec<String>);

fn group_state<F: quotern_core::ingest::fs::SourceFs>(
    engine: &OpenCodeEngine<F>,
    id: &str,
) -> TestResult<GroupState> {
    let records = engine.observations_page(None, 1_000)?.observations;
    let record = find(&records, id);
    Ok((
        record.input.value,
        record.revision,
        record.pending_partial,
        record.pending_reason,
        record.selected_part_ids.clone(),
    ))
}

/// One part of the combined group: five explicit components with an explicit total.
fn group_part(input: u64) -> Value {
    step_finish(counts(
        Some(input),
        Some(0),
        Some(0),
        Some(0),
        Some(0),
        Some(input),
    ))
}

/// Every consumer of group `g` agrees on one expected state: the decoded history page, the decoded
/// source snapshot, the durable event row, its maintained group row and the maintained totals.
/// `report` is an actual report of the engine (or of the pass that last ran); the snapshot only
/// carries its outcome, failure and last-good time, which are asserted to round-trip.
fn assert_g_consumers<F: quotern_core::ingest::fs::SourceFs>(
    engine: &OpenCodeEngine<F>,
    report: &PassReport,
    data: &Path,
    sqlite: bool,
    expected: (u64, u64, bool, Option<FailureCode>),
) -> TestResult {
    use quotern_core::domain::{AcquisitionConsistency, ProjectionConsistency};
    use quotern_core::snapshot::{ObservationPage, SourceSnapshot};
    let (value, revision, pending, reason) = expected;
    let (acquisition, projection_consistency) = if sqlite {
        (
            AcquisitionConsistency::SqliteReadTransaction,
            ProjectionConsistency::SqliteReadTransaction,
        )
    } else {
        (
            AcquisitionConsistency::FileByFileBestEffort,
            ProjectionConsistency::FileByFileBestEffort,
        )
    };
    let parts = vec!["p1".to_owned(), "p2".to_owned()];
    let page = ObservationPage::decode(&serde_json::to_vec(&engine.observations_page(None, 10)?)?)?;
    assert_eq!(page.observations.len(), 1);
    let g = find(&page.observations, "g");
    assert_eq!(
        values(g),
        [Some(value), Some(0), Some(0), Some(0), Some(0), Some(value)]
    );
    assert_eq!(
        (g.revision, g.pending_partial, g.pending_reason),
        (revision, pending, reason)
    );
    assert_eq!(g.selected_part_ids, parts);
    assert_eq!(g.total.provenance, Some(Provenance::Reported));
    assert_eq!(g.source_convention, None);
    assert_eq!(g.acquisition_consistency, acquisition);
    assert!(!g.total_mismatch && !g.mirror_conflict);

    let snapshot = SourceSnapshot::decode(&serde_json::to_vec(&engine.snapshot(report)?)?)?;
    assert_eq!(
        (snapshot.outcome, snapshot.failure, snapshot.last_good_ms),
        (report.outcome, report.failure, report.last_good_ms)
    );
    assert_eq!(snapshot.projection.records, 1);
    assert_eq!(
        (
            snapshot.projection.input.value,
            snapshot.projection.total.value
        ),
        (Some(value), Some(value))
    );
    assert_eq!(snapshot.projection.pending_partial, pending);
    assert_eq!(
        snapshot.projection.acquisition_consistency,
        Some(projection_consistency)
    );

    let (input, expected_value) = (i64::try_from(value)?, i64::try_from(value)?);
    type Event = (Option<i64>, Option<i64>, i64, i64, Option<String>, String);
    let event: Event = history(data)?.query_row(
        "SELECT input_tokens, total_tokens, revision, pending_partial, pending_reason, \
         selected_part_ids FROM usage_events WHERE source_id = ?1 AND message_id = 'g'",
        [&snapshot.source_id],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        },
    )?;
    assert_eq!(
        (event.0, event.1, event.2, event.3),
        (
            Some(input),
            Some(expected_value),
            i64::try_from(revision)?,
            i64::from(pending)
        )
    );
    assert_eq!(event.4, reason.map(|code| code.as_str().to_owned()));
    assert_eq!(serde_json::from_str::<Vec<String>>(&event.5)?, parts);
    let groups: Vec<Event> = history(data)?
        .prepare(
            "SELECT input_tokens, total_tokens, 0, pending_partial, pending_reason, part_ids \
             FROM reported_groups WHERE source_id = ?1 AND message_id = 'g'",
        )?
        .query_map([&snapshot.source_id], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    assert_eq!(groups.len(), 1, "one maintained group row: {groups:?}");
    assert_eq!(
        (groups[0].0, groups[0].1, groups[0].3),
        (Some(input), Some(expected_value), i64::from(pending))
    );
    assert_eq!(groups[0].4, reason.map(|code| code.as_str().to_owned()));
    assert_eq!(serde_json::from_str::<Vec<String>>(&groups[0].5)?, parts);
    let totals: (i64, i64, i64, i64, i64, i64) = history(data)?.query_row(
        "SELECT records, input_sum, total_sum, pending_count, json_count, sqlite_count \
         FROM source_projection_totals WHERE source_id = ?1",
        [&snapshot.source_id],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        },
    )?;
    assert_eq!(
        totals,
        (
            1,
            input,
            expected_value,
            i64::from(pending),
            i64::from(!sqlite),
            i64::from(sqlite)
        )
    );
    Ok(())
}

#[test]
fn group_cursor_fault_reopen_atomic() -> TestResult {
    use quotern_core::store::FaultPoint;
    let _guard = vfs_test_guard();
    let part = |input: u64| {
        step_finish(counts(
            Some(input),
            Some(0),
            Some(0),
            Some(0),
            Some(0),
            Some(input),
        ))
    };
    for fault in [FaultPoint::BeforeCommit, FaultPoint::AfterCommit] {
        let directory = tempdir()?;
        let (source, data, home) = source_roots(directory.path())?;
        let c = open_fixture(&source.join("opencode.db"))?;
        // G1: p1 = 40, p2 = 60 complete the group at 100.
        put_message(&c, "g", "s", T0, &json!({"role": "assistant"}))?;
        put_part(&c, "p1", "g", "s", &part(40))?;
        put_part(&c, "p2", "g", "s", &part(60))?;
        let mut engine = open_engine(&source, &data, &home)?;
        let g1 = engine.pass(consented(), 1);
        assert_eq!(g1.outcome, PassOutcome::Consistent, "{g1:?}");
        let both = vec!["p1".to_owned(), "p2".to_owned()];
        assert_eq!(
            group_state(&engine, "g")?,
            (Some(100), 1, false, None, both.clone())
        );
        assert_g_consumers(&engine, &g1, &data, true, (100, 1, false, None))?;
        drop(engine);
        // Reopen between G1 and the next change; the prune retains the complete group as pending.
        let mut engine = open_engine(&source, &data, &home)?;
        c.execute("DELETE FROM part WHERE id = 'p2'", [])?;
        let prune = engine.pass(consented(), 100_000);
        assert_eq!(prune.outcome, PassOutcome::Partial, "{prune:?}");
        assert_eq!(
            group_state(&engine, "g")?,
            (
                Some(100),
                1,
                true,
                Some(FailureCode::InvalidRecord),
                both.clone()
            )
        );
        assert_g_consumers(
            &engine,
            &prune,
            &data,
            true,
            (100, 1, true, Some(FailureCode::InvalidRecord)),
        )?;
        // G2: p2 comes back as an explicit zero, which authoritatively revises the group to 40.
        put_part(&c, "p2", "g", "s", &part(0))?;
        let before = (
            scalar::<i64>(&data, "SELECT generation FROM sources")?,
            scalar::<i64>(&data, "SELECT revision FROM usage_events")?,
        );
        // Every earlier pass ended in a finalized generation: no cursor, frontier, metadata,
        // staged candidate or baseline row exists before the faulted pass.
        let pre = durable_acquisition(&data)?;
        assert_acquisition_cleared(&pre, &format!("{fault:?} before the faulted pass"));
        assert_eq!(pre.counters.0, before.0);
        engine.inject_commit_fault(fault);
        let faulted = engine.pass(consented(), 200_000);
        assert_eq!(
            faulted.failure,
            Some(FailureCode::Store),
            "{fault:?}: {faulted:?}"
        );
        drop(engine);
        let mut engine = open_engine(&source, &data, &home)?;
        // Read immediately after the reopen, before any later pass could repair a half state.
        let landed = durable_acquisition(&data)?;
        match fault {
            FaultPoint::BeforeCommit => {
                // Atomic: nothing of the new membership, value, pending flag or generation landed.
                assert_eq!(
                    group_state(&engine, "g")?,
                    (
                        Some(100),
                        1,
                        true,
                        Some(FailureCode::InvalidRecord),
                        both.clone()
                    )
                );
                assert_g_consumers(
                    &engine,
                    &faulted,
                    &data,
                    true,
                    (100, 1, true, Some(FailureCode::InvalidRecord)),
                )?;
                assert_eq!(
                    scalar::<i64>(&data, "SELECT generation FROM sources")?,
                    before.0
                );
                assert_eq!(
                    scalar::<i64>(&data, "SELECT COUNT(*) FROM opencode_progress")?,
                    0,
                    "no half-saved cursor"
                );
                // Cursor, frontier, metadata, candidates, baselines, counters and inventory are
                // exactly the pre-pass rows.
                assert_eq!(landed, pre, "nothing of the faulted generation landed");
            }
            FaultPoint::AfterCommit => {
                assert_eq!(
                    group_state(&engine, "g")?,
                    (Some(40), 2, false, None, both.clone())
                );
                assert_eq!(
                    scalar::<i64>(&data, "SELECT generation FROM sources")?,
                    before.0 + 1
                );
                assert_g_consumers(&engine, &faulted, &data, true, (40, 2, false, None))?;
                // The same transaction published the group and finalized the generation: the
                // cursor the pass saved, its metadata, candidates and baseline are gone with it.
                assert_acquisition_cleared(&landed, "after the committed generation");
                assert_eq!(
                    landed.counters,
                    (before.0 + 1, 0, None, None, None, 0),
                    "generation advanced once, clean and without retry state"
                );
                assert_eq!(landed.failures, pre.failures);
                assert_eq!(
                    landed
                        .files
                        .iter()
                        .map(|file| (file.0.as_str(), file.5.as_str(), file.6, file.7.as_str()))
                        .collect::<Vec<_>>(),
                    [("opencode.db", "sqlite", before.0, "present")],
                    "the inventory names the generation that was committed"
                );
            }
        }
        // Stable reacquisition converges on 40 with exactly one revision step, never a duplicate.
        let reports = run_until_consistent(&mut engine, 300_000, 6);
        assert_eq!(
            reports.last().ok_or("pass")?.outcome,
            PassOutcome::Consistent,
            "{fault:?}: {reports:?}"
        );
        assert_eq!(
            group_state(&engine, "g")?,
            (Some(40), 2, false, None, both.clone()),
            "{fault:?}"
        );
        assert_g_consumers(
            &engine,
            reports.last().ok_or("pass")?,
            &data,
            true,
            (40, 2, false, None),
        )?;
        let after = run_until_consistent(&mut engine, 5_000_000, 3);
        assert_eq!(after.last().ok_or("pass")?.outcome, PassOutcome::Consistent);
        assert_eq!(
            group_state(&engine, "g")?.1,
            2,
            "{fault:?}: no duplicate revision"
        );
        assert_g_consumers(
            &engine,
            after.last().ok_or("pass")?,
            &data,
            true,
            (40, 2, false, None),
        )?;
    }
    Ok(())
}

type Baseline = Vec<(String, i64, String, Option<String>)>;

/// Generation, staged candidate rows of that generation and its pre-generation group baseline, read
/// from the durable store.
fn acquisition_state(data: &Path) -> TestResult<(i64, i64, Baseline)> {
    let connection = history(data)?;
    let generation: i64 =
        connection.query_row("SELECT generation FROM sources", [], |row| row.get(0))?;
    let spool = connection.query_row(
        "SELECT COUNT(*) FROM opencode_candidate_spool WHERE generation = ?1",
        [generation],
        |row| row.get(0),
    )?;
    let baseline = connection
        .prepare(
            "SELECT event_key, format_rank, mirror_path, prior_json FROM group_baseline \
             WHERE generation = ?1 ORDER BY event_key, format_rank, mirror_path",
        )?
        .query_map([generation], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok((generation, spool, baseline))
}

/// Everything the store durably says about one source's progress, status and history rows.
type Durable = (
    i64,
    (String, Option<String>, Option<i64>),
    Vec<(String, Option<i64>, i64, i64)>,
);

fn durable_view(data: &Path) -> TestResult<Durable> {
    let connection = history(data)?;
    let generation =
        connection.query_row("SELECT generation FROM sources", [], |row| row.get(0))?;
    let status = connection.query_row(
        "SELECT outcome, last_error_code, last_success_ms FROM source_status",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let events = connection
        .prepare(
            "SELECT event_key, input_tokens, revision, pending_partial FROM usage_events \
             ORDER BY event_key",
        )?
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok((generation, status, events))
}

type ProgressRow = (String, i64, Option<String>, Option<String>);
type FrontierRow = (String, i64, i64, i64, i64);
type MetadataRow = (String, i64, i64, i64, i64, i64, String);
type SpoolRow = (String, i64, String, i64, String, String);
type BaselineRow = (String, i64, i64, String, Option<String>);
type FailureRow = (String, String, i64);
type FileRow = (String, i64, i64, i64, i64, String, i64, String, i64);
type CounterRow = (i64, i64, Option<i64>, Option<String>, Option<String>, i64);

/// Every durable row of the acquisition-local state of a source (working cursors, directory
/// frontier, file metadata, staged candidates, group baselines, failures) beside the generation
/// counters and the published file inventory, read with plain SQL. Compared as a whole, so a
/// half-landed or half-removed piece of any of them changes the value.
#[derive(Debug, PartialEq)]
struct Acquisition {
    /// generation, change count, next retry, retry reason, sticky generation failure, dirty.
    counters: CounterRow,
    progress: Vec<ProgressRow>,
    frontier: Vec<FrontierRow>,
    metadata: Vec<MetadataRow>,
    spool: Vec<SpoolRow>,
    baseline: Vec<BaselineRow>,
    failures: Vec<FailureRow>,
    files: Vec<FileRow>,
}

fn sql_rows<T>(
    connection: &Connection,
    sql: &str,
    row: impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
) -> TestResult<Vec<T>> {
    Ok(connection
        .prepare(sql)?
        .query_map([], row)?
        .collect::<rusqlite::Result<_>>()?)
}

fn durable_acquisition(data: &Path) -> TestResult<Acquisition> {
    let connection = history(data)?;
    Ok(Acquisition {
        counters: connection.query_row(
            "SELECT generation, change_count, next_retry_ms, retry_reason, generation_failure, \
             dirty FROM sources",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )?,
        progress: sql_rows(
            &connection,
            "SELECT acquisition_path, generation, working_cursor_key, identity \
             FROM opencode_progress ORDER BY acquisition_path",
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?,
        frontier: sql_rows(
            &connection,
            "SELECT relative_path, generation, depth, ordinal, restart_blocked \
             FROM frontier_directories ORDER BY generation, ordinal",
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?,
        metadata: sql_rows(
            &connection,
            "SELECT relative_path, generation, device, inode, size, mtime_ns, parser_kind \
             FROM metadata_spool ORDER BY generation, relative_path",
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            },
        )?,
        spool: sql_rows(
            &connection,
            "SELECT relative_path, generation, event_key, format_rank, fingerprint, \
             candidate_json FROM opencode_candidate_spool ORDER BY generation, relative_path, \
             event_key, format_rank, fingerprint",
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )?,
        baseline: sql_rows(
            &connection,
            "SELECT event_key, generation, format_rank, mirror_path, prior_json \
             FROM group_baseline ORDER BY generation, event_key, format_rank, mirror_path",
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?,
        failures: sql_rows(
            &connection,
            "SELECT relative_path, code, attempts FROM acquisition_failures \
             ORDER BY relative_path",
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?,
        files: sql_rows(
            &connection,
            "SELECT relative_path, device, inode, size, mtime_ns, adapter_state, \
             parse_generation, file_state, visit_seq FROM source_files ORDER BY relative_path",
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )?,
    })
}

/// No acquisition-local row of any kind remains: the generation was finalized or discarded as a
/// whole, with its cursors, frontier, metadata, staged candidates and baselines.
fn assert_acquisition_cleared(state: &Acquisition, label: &str) {
    assert!(
        state.progress.is_empty()
            && state.frontier.is_empty()
            && state.metadata.is_empty()
            && state.spool.is_empty()
            && state.baseline.is_empty(),
        "{label}: acquisition-local rows remain: {state:?}"
    );
}

/// Positions of the backlog database `database` and of the `storage` directory among the entries
/// of `root`, in the order the native listing of that very directory yields them: the order the
/// engine walks its root entries.
fn root_positions(root: &Path, database: &str) -> TestResult<(usize, usize)> {
    let listed = std::fs::read_dir(root)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    let position = |name: &str| {
        listed
            .iter()
            .position(|entry| entry == name)
            .ok_or_else(|| format!("{name} is not among the root entries {listed:?}"))
    };
    Ok((position(database)?, position("storage")?))
}

/// A file name for the backlog database that the native listing of the ACTUAL source root yields
/// before (`backlog_first`) or after the `storage` directory there. Each of eight candidate names
/// is tried in turn by placing an empty file of that name in `source` itself, reading the real
/// listing of `source` and removing the file again (so nothing temporary is left for the engine),
/// never by predicting from another directory. Setup fails when none of them gives the order.
fn backlog_name(source: &Path, backlog_first: bool) -> TestResult<&'static str> {
    let mut tried = Vec::new();
    for name in [
        "opencode-backlog.db",
        "opencode-z.db",
        "opencode-a.db",
        "opencode-b.db",
        "opencode-0.db",
        "opencode-zbacklog.db",
        "opencode-m.db",
        "opencode-q.db",
    ] {
        let placeholder = source.join(name);
        std::fs::write(&placeholder, b"")?;
        let positions = root_positions(source, name);
        std::fs::remove_file(&placeholder)?;
        let (database, storage) = positions?;
        if (database < storage) == backlog_first {
            return Ok(name);
        }
        tried.push((name, database, storage));
    }
    Err(format!(
        "no backlog name is listed {} in {source:?}; (name, database, storage) tried: {tried:?}",
        if backlog_first {
            "before storage"
        } else {
            "after storage"
        }
    )
    .into())
}

/// Native rollback database of 5,100 valid non-usage legacy messages: no numeric observation, but
/// more rows than one pass reads, so the generation stays unfinished across passes.
fn non_usage_backlog(source: &Path, name: &str) -> TestResult<Connection> {
    let connection = open_fixture(&source.join(name))?;
    let transaction = connection.unchecked_transaction()?;
    for index in 0..5_100_i64 {
        put_message(
            &transaction,
            &format!("backlog-{index:05}"),
            "backlog",
            T0 + index,
            &json!({"role": "user"}),
        )?;
    }
    transaction.commit()?;
    Ok(connection)
}

/// The backlog database's saved cursor exists and is not complete: the generation is unfinished.
fn assert_backlog_unfinished(data: &Path, name: &str) -> TestResult {
    let cursor: Option<String> = history(data)?.query_row(
        "SELECT working_cursor_key FROM opencode_progress WHERE acquisition_path = ?1",
        [name],
        |row| row.get(0),
    )?;
    assert_eq!(
        quotern_core::adapters::opencode::cursor_is_complete(cursor.as_deref()),
        Ok(false),
        "{cursor:?}"
    );
    Ok(())
}

/// The durable position before the faulted G3 pass, read with plain SQL and from the backlog
/// database itself: a saved non-NULL working cursor inside the backlog (so the generation is
/// unfinished and resumes from it), fewer rows after that cursor than one pass reads (so the next
/// pass ends the backlog), the directory frontier that is still open (the root, and `storage`
/// unless the listing order left it to the known-file lane, whose remaining listing is a handful of
/// entries), and the first competitor staged, payload included, under its baseline.
/// A pass from this position reaches the terminal resolution of the second competitor, where the
/// discard takes the injected fault, and never ends earlier in a staging write. Returns the rows and
/// the number of backlog rows after the cursor.
fn assert_terminal_replay_position(
    data: &Path,
    backlog: &Connection,
    name: &str,
    first: u64,
    label: &str,
) -> TestResult<(Acquisition, i64)> {
    let state = durable_acquisition(data)?;
    let generation = state.counters.0;
    let cursor = state
        .progress
        .iter()
        .find(|row| row.0 == name)
        .and_then(|row| row.2.clone())
        .ok_or_else(|| format!("{label}: no non-NULL backlog cursor: {state:?}"))?;
    assert_eq!(
        quotern_core::adapters::opencode::cursor_is_complete(Some(&cursor)),
        Ok(false),
        "{label}: {cursor}"
    );
    let saved: Value = serde_json::from_str(&cursor)?;
    assert_eq!(
        saved["v2"],
        json!({"rowid": null, "done": false}),
        "{label}: {cursor}"
    );
    assert_eq!(saved["legacy"]["done"], json!(false), "{label}: {cursor}");
    let position = saved["legacy"]["rowid"]
        .as_i64()
        .ok_or_else(|| format!("{label}: cursor without a row position: {cursor}"))?;
    let remaining: i64 = backlog.query_row(
        "SELECT COUNT(*) FROM message WHERE rowid > ?1",
        [position],
        |row| row.get(0),
    )?;
    assert_eq!(position + remaining, 5_100, "{label}: {cursor}");
    // One pass reads up to 5,000 rows, half of that on the reserved current lane.
    assert!(
        (1..=2_500).contains(&remaining),
        "{label}: {remaining} rows remain after the saved cursor"
    );
    // Which root entries are still open depends on the order the native listing yielded them: the
    // root alone (the backlog database came first and `storage` was read through the known-file
    // lane), or the root and then `storage`. Both are legal variants of one frontier; nothing else
    // is, and neither is blocked for restart. What remains of it is a handful of directories, far
    // inside the per-pass directory ceiling the conflict pass is held to afterwards.
    let legal = [("", 0_i64), ("storage", 1)];
    let frontier = state
        .frontier
        .iter()
        .map(|row| (row.0.as_str(), row.1, row.2, row.3, row.4))
        .collect::<Vec<_>>();
    assert!(
        (1..=legal.len()).contains(&frontier.len())
            && frontier
                .iter()
                .zip(legal)
                .all(|(row, (path, depth))| *row == (path, generation, depth, depth, 0)),
        "{label}: open directory frontier {frontier:?}"
    );
    assert_eq!(
        state
            .metadata
            .iter()
            .map(|row| (row.0.as_str(), row.1, row.6.as_str()))
            .collect::<Vec<_>>(),
        [
            (name, generation, "sqlite"),
            (
                "storage/message/sj/g.json",
                generation,
                "opencode_json_message"
            ),
            ("storage/part/g", generation, "directory"),
            ("storage/part/g/p1.json", generation, "opencode_json_part"),
            ("storage/part/g/p2.json", generation, "opencode_json_part"),
        ],
        "{label}: file metadata"
    );
    assert_eq!(
        state
            .spool
            .iter()
            .map(|row| (row.0.as_str(), row.1, row.2.as_str(), row.3))
            .collect::<Vec<_>>(),
        [(
            "storage/message/sj/g.json",
            generation,
            "opencode:2:sj:1:g",
            2
        )],
        "{label}: staged first competitor"
    );
    // The staged payload itself, not only its key and fingerprint: the first competitor's exact
    // fixture values, and the fingerprint column is the payload's own.
    let staged: Value = serde_json::from_str(&state.spool[0].5)?;
    assert_eq!(
        staged["components"],
        json!({"input": first, "output": 0, "reasoning": 0, "cache_read": 0, "cache_write": 0}),
        "{label}: {staged}"
    );
    assert_eq!(staged["total"], json!(first), "{label}: {staged}");
    assert_eq!(staged["total_provenance"], json!("reported"), "{label}");
    assert_eq!(staged["selected_part_ids"], json!(["p1", "p2"]), "{label}");
    assert_eq!(staged["pending_partial"], json!(false), "{label}");
    assert_eq!(staged["format_rank"], json!(2), "{label}");
    assert_eq!(
        staged["relative_path"],
        json!("storage/message/sj/g.json"),
        "{label}"
    );
    assert_eq!(
        format!("{:016x}", staged["fingerprint"].as_u64().unwrap_or(0)),
        state.spool[0].4,
        "{label}: fingerprint column"
    );
    assert_eq!(
        state
            .baseline
            .iter()
            .map(|row| (
                row.0.as_str(),
                row.1,
                row.2,
                row.3.as_str(),
                row.4.is_some()
            ))
            .collect::<Vec<_>>(),
        [(
            "opencode:2:sj:1:g",
            generation,
            2,
            "storage/message/sj/g.json",
            true
        )],
        "{label}: pre-generation baseline"
    );
    Ok((state, remaining))
}

/// One JSON group `g` in every combined step: valid parent without usage, `p1` fixed at 40 and
/// `p2` revised through 100, a pruned part, an explicit zero (40) and two competing acquisitions of
/// the same rank and path (41 then 42, and 42 then 41), each with the commit of the revision (G2)
/// and of the conflict handling (G3) faulted before, after or not at all.
#[test]
fn revision_generation_tie_fault_reopen() -> TestResult {
    use quotern_core::store::FaultPoint;
    let _guard = vfs_test_guard();
    let invalid = Some(FailureCode::InvalidRecord);
    let changing = Some(FailureCode::SourceChanging);
    // The order the actual source root listed the backlog database and `storage` in, per case.
    let mut witnessed = Vec::new();
    for (first, second) in [(41_u64, 42_u64), (42, 41)] {
        for (fault, backlog_first) in [
            None,
            Some(FaultPoint::BeforeCommit),
            Some(FaultPoint::AfterCommit),
        ]
        .into_iter()
        .flat_map(|fault| [(fault, false), (fault, true)])
        {
            let label = format!("{first}/{second} {fault:?} backlog_first={backlog_first}");
            let directory = tempdir()?;
            let (source, data, home) = source_roots(&directory.path().canonicalize()?)?;
            write_json_message(&source, "sj", "g", T0, None)?;
            write_json_part(&source, "g", "p1", &group_part(40))?;
            write_json_part(&source, "g", "p2", &group_part(60))?;

            // G1: the clean group.
            let mut engine = open_engine(&source, &data, &home)?;
            let g1 = engine.pass(consented(), 1);
            assert_eq!(g1.outcome, PassOutcome::Consistent, "{label}: {g1:?}");
            assert_g_consumers(&engine, &g1, &data, false, (100, 1, false, None))?;
            drop(engine);
            let mut engine = open_engine(&source, &data, &home)?;

            // Prune: a missing part is not an explicit zero; the complete group is retained.
            std::fs::remove_file(source.join("storage/part/g/p2.json"))?;
            let prune = engine.pass(consented(), 100_000);
            assert_eq!(
                (prune.outcome, prune.failure),
                (PassOutcome::Partial, invalid),
                "{label}: {prune:?}"
            );
            assert_g_consumers(&engine, &prune, &data, false, (100, 1, true, invalid))?;

            // G2: p2 returns as an explicit zero, which authoritatively revises the group to 40.
            write_json_part(&source, "g", "p2", &group_part(0))?;
            let before = durable_view(&data)?;
            let pre = durable_acquisition(&data)?;
            assert_acquisition_cleared(&pre, &format!("{label}: before G2"));
            let mut last = if let Some(point) = fault {
                engine.inject_commit_fault(point);
                let faulted = engine.pass(consented(), 200_000);
                assert_eq!(
                    faulted.failure,
                    Some(FailureCode::Store),
                    "{label}: {faulted:?}"
                );
                drop(engine);
                engine = open_engine(&source, &data, &home)?;
                // Read immediately after the reopen, before any later pass could repair a half
                // state.
                let landed = durable_acquisition(&data)?;
                match point {
                    FaultPoint::BeforeCommit => {
                        assert_g_consumers(
                            &engine,
                            &faulted,
                            &data,
                            false,
                            (100, 1, true, invalid),
                        )?;
                        assert_eq!(durable_view(&data)?, before, "{label}: nothing landed");
                        assert_eq!(landed, pre, "{label}: no cursor, frontier or spool landed");
                    }
                    FaultPoint::AfterCommit => {
                        assert_g_consumers(&engine, &faulted, &data, false, (40, 2, false, None))?;
                        assert_eq!(
                            scalar::<i64>(&data, "SELECT generation FROM sources")?,
                            before.0 + 1,
                            "{label}: generation advanced exactly once"
                        );
                        assert_acquisition_cleared(&landed, &format!("{label}: committed G2"));
                        assert_eq!(
                            landed.counters,
                            (before.0 + 1, 0, None, None, None, 0),
                            "{label}"
                        );
                        assert_eq!(landed.failures, pre.failures, "{label}");
                    }
                }
                let reports = run_until_consistent(&mut engine, 300_000, 6);
                reports.last().ok_or("pass")?.clone()
            } else {
                engine.pass(consented(), 200_000)
            };
            assert_eq!(last.outcome, PassOutcome::Consistent, "{label}: {last:?}");
            assert_g_consumers(&engine, &last, &data, false, (40, 2, false, None))?;
            drop(engine);
            let mut engine = open_engine(&source, &data, &home)?;
            let reports = run_until_consistent(&mut engine, 5_000_000, 3);
            last = reports.last().ok_or("pass")?.clone();
            assert_eq!(last.outcome, PassOutcome::Consistent, "{label}: {last:?}");
            assert_g_consumers(&engine, &last, &data, false, (40, 2, false, None))?;

            // G3: a backlog keeps the next generation unfinished while p2 changes twice.
            let backlog_name = backlog_name(&source, backlog_first)?;
            let backlog = non_usage_backlog(&source, backlog_name)?;
            let (database, storage) = root_positions(&source, backlog_name)?;
            let listed_first = database < storage;
            println!(
                "ROOT-ORDER {label}: database@{database} storage@{storage} backlog_first={listed_first}"
            );
            assert_eq!(
                listed_first, backlog_first,
                "{label}: actual source-root order: database@{database} storage@{storage}"
            );
            witnessed.push(listed_first);
            write_json_part(&source, "g", "p2", &group_part(first - 40))?;
            // Nothing reordered the root since: the engine pass below walks it in this order.
            let (database, storage) = root_positions(&source, backlog_name)?;
            assert_eq!(
                database < storage,
                backlog_first,
                "{label}: actual source-root order before the staged pass: database@{database} storage@{storage}"
            );
            let mut now = 10_000_000_i64;
            let generation = scalar::<i64>(&data, "SELECT generation FROM sources")?;
            let staged = engine.pass(consented(), now);
            assert_eq!(
                staged.outcome,
                PassOutcome::CatchingUp,
                "{label}: {staged:?}"
            );
            assert_g_consumers(&engine, &staged, &data, false, (first, 3, false, None))?;
            let unfinished = acquisition_state(&data)?;
            assert_eq!(unfinished.0, generation, "{label}: same generation");
            assert!(unfinished.1 > 0, "{label}: durable acquisition spool");
            assert!(!unfinished.2.is_empty(), "{label}: durable baseline");
            drop(engine);
            let mut engine = open_engine(&source, &data, &home)?;
            now += 1;
            let rebuilt = engine.pass(consented(), now);
            assert_ne!(
                rebuilt.outcome,
                PassOutcome::Consistent,
                "{label}: {rebuilt:?}"
            );
            assert_g_consumers(&engine, &rebuilt, &data, false, (first, 3, false, None))?;
            assert_eq!(
                acquisition_state(&data)?,
                unfinished,
                "{label}: baseline and spool intact"
            );

            write_json_part(&source, "g", "p2", &group_part(second - 40))?;
            assert_backlog_unfinished(&data, backlog_name)?;
            let pre_fault = acquisition_state(&data)?;
            let (pre_fault_full, remaining) =
                assert_terminal_replay_position(&data, &backlog, backlog_name, first, &label)?;
            assert_eq!(pre_fault_full.counters.0, pre_fault.0, "{label}");
            if let Some(point) = fault {
                engine.inject_commit_fault(point);
            }
            now += 1;
            let conflict_time = now;
            let conflict = engine.pass(consented(), conflict_time);
            // The pass read every row after the saved cursor and no per-pass ceiling (the literal
            // current-lane halves of 5,000 rows, 20,000 entries, 40,000 metadata calls and 64
            // directory opens) cut it short, so it ended the backlog and its frontier and met the
            // second competitor in the terminal resolution (the discard), not in an earlier
            // staging write that would have taken the fault.
            let work = conflict.counters;
            assert!(
                i64::from(work.rows_read) >= remaining
                    && work.rows_read < 2_500
                    && work.entries < 10_000
                    && work.stat_calls < 20_000
                    && work.directory_opens < 32,
                "{label}: {remaining} rows remained: {conflict:?}"
            );
            let conflict = match fault {
                None => {
                    assert_eq!(conflict.failure, changing, "{label}: {conflict:?}");
                    assert_acquisition_cleared(&durable_acquisition(&data)?, &label);
                    conflict
                }
                Some(point) => {
                    assert_eq!(
                        (conflict.outcome, conflict.failure),
                        (PassOutcome::Partial, Some(FailureCode::Store)),
                        "{label}: {conflict:?}"
                    );
                    drop(engine);
                    engine = open_engine(&source, &data, &home)?;
                    // Read immediately after the reopen, before any later pass.
                    let landed = durable_acquisition(&data)?;
                    match point {
                        FaultPoint::BeforeCommit => {
                            // Nothing of the restore landed: the first competitor is still
                            // published with its durable acquisition and baseline.
                            assert_g_consumers(
                                &engine,
                                &conflict,
                                &data,
                                false,
                                (first, 3, false, None),
                            )?;
                            assert_eq!(acquisition_state(&data)?, pre_fault, "{label}");
                            assert_eq!(
                                landed, pre_fault_full,
                                "{label}: cursor, frontier, metadata, spool and baseline"
                            );
                            let mut replayed = None;
                            for _ in 0..6 {
                                now += 400_000;
                                let report = engine.pass(consented(), now);
                                assert_ne!(
                                    report.outcome,
                                    PassOutcome::Consistent,
                                    "{label}: {report:?}"
                                );
                                if report.failure == changing {
                                    replayed = Some(report);
                                    break;
                                }
                            }
                            replayed.ok_or("the conflict was never replayed")?
                        }
                        FaultPoint::AfterCommit => {
                            // The discard itself committed: restore, pending flag and backoff.
                            assert_g_consumers(
                                &engine,
                                &conflict,
                                &data,
                                false,
                                (40, 4, true, changing),
                            )?;
                            // The discard removed the whole acquisition with its restore: the
                            // cursor, frontier, metadata, candidate and baseline rows are gone,
                            // the generation stays open and the source is dirty and backing off.
                            assert_acquisition_cleared(&landed, &label);
                            assert_eq!(
                                (landed.counters.0, landed.counters.1, landed.counters.5),
                                (pre_fault_full.counters.0, 1, 1),
                                "{label}"
                            );
                            let retry = retry_row(&data)?;
                            assert_eq!(
                                (retry.0, retry.2.as_deref()),
                                (1, Some("source_changing")),
                                "{label}: {retry:?}"
                            );
                            assert!(
                                retry.1.is_some_and(|deadline| deadline > conflict_time),
                                "{retry:?}"
                            );
                            assert_eq!(
                                scalar::<Option<String>>(
                                    &data,
                                    "SELECT last_error_code FROM source_status"
                                )?,
                                Some("source_changing".to_owned())
                            );
                            now = conflict_time + 1;
                            let inside_backoff = engine.pass(consented(), now);
                            assert_eq!(
                                inside_backoff.failure, changing,
                                "{label}: {inside_backoff:?}"
                            );
                            inside_backoff
                        }
                    }
                }
            };
            assert_g_consumers(&engine, &conflict, &data, false, (40, 4, true, changing))?;
            assert_eq!(
                scalar::<i64>(&data, "SELECT dirty FROM sources")?,
                1,
                "{label}"
            );

            // The retry after the backoff is stable and reaches the second competitor, once.
            let mut settled = None;
            for _ in 0..24 {
                now += 400_000;
                let report = engine.pass(consented(), now);
                if report.outcome == PassOutcome::Consistent {
                    settled = Some(report);
                    break;
                }
            }
            let settled = settled.ok_or("the retry never reached a clean generation")?;
            assert_eq!(settled.failure, None, "{label}: {settled:?}");
            assert_g_consumers(&engine, &settled, &data, false, (second, 5, false, None))?;
            assert_eq!(
                scalar::<i64>(&data, "SELECT dirty FROM sources")?,
                0,
                "{label}"
            );
            let again = run_until_consistent(&mut engine, now + 400_000, 3);
            let again = again.last().ok_or("pass")?;
            assert_eq!(again.outcome, PassOutcome::Consistent, "{label}: {again:?}");
            assert_g_consumers(&engine, again, &data, false, (second, 5, false, None))?;
            drop(engine);
            let mut engine = open_engine(&source, &data, &home)?;
            let reopened = run_until_consistent(&mut engine, now + 4_000_000, 3);
            let reopened = reopened.last().ok_or("pass")?;
            assert_eq!(
                reopened.outcome,
                PassOutcome::Consistent,
                "{label}: {reopened:?}"
            );
            assert_g_consumers(&engine, reopened, &data, false, (second, 5, false, None))?;
        }
    }
    assert_eq!(witnessed.len(), 12, "{witnessed:?}");
    assert!(
        witnessed.iter().filter(|first| **first).count() == 6
            && witnessed.iter().filter(|first| !**first).count() == 6,
        "both actual source-root orders must be witnessed, six cases each: {witnessed:?}"
    );
    Ok(())
}

fn retry_row(data: &Path) -> TestResult<(i64, Option<i64>, Option<String>)> {
    Ok(history(data)?.query_row(
        "SELECT change_count, next_retry_ms, retry_reason FROM sources",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?)
}

#[test]
fn idle_and_busy_sources_back_off_durably_on_the_injected_clock() -> TestResult {
    let _guard = vfs_test_guard();
    // Idle: a cleanly closed WAL database has no sidecars.
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let database = source.join("opencode.db");
    let mut writer = start_writer(&database)?;
    writer.stop()?;
    let fs = RecordingFs::new();
    let observed = fs.clone();
    let mut engine = open_recording_engine(fs, &source, &data, &home)
        .map_err(|report| format!("OpenCode engine failed: {report:?}"))?;
    let first = engine.pass(consented(), 1_000);
    assert_eq!(
        (first.outcome, first.failure),
        (PassOutcome::Unavailable, Some(FailureCode::SourceIdle))
    );
    assert_eq!(
        retry_row(&data)?,
        (1, Some(6_000), Some("source_idle".to_owned()))
    );
    // One millisecond before the deadline: no physical source work, the same classification.
    let before = observed.metrics();
    let gated = engine.pass(consented(), 5_999);
    assert_eq!(
        (gated.outcome, gated.failure),
        (PassOutcome::Unavailable, Some(FailureCode::SourceIdle))
    );
    assert_eq!(
        observed.metrics(),
        before,
        "no read, open or stat at deadline - 1"
    );
    assert_eq!(gated.counters, Default::default());
    // The deadline survives a reopen.
    drop(engine);
    let fs = RecordingFs::new();
    let observed = fs.clone();
    let mut engine = open_recording_engine(fs, &source, &data, &home)
        .map_err(|report| format!("OpenCode engine failed: {report:?}"))?;
    let before = observed.metrics();
    let reopened = engine.pass(consented(), 5_999);
    assert_eq!(reopened.failure, Some(FailureCode::SourceIdle));
    assert_eq!(
        observed.metrics(),
        before,
        "reopened engine honours the persisted deadline"
    );
    // At the deadline the permitted attempt happens, and the delay doubles.
    let at = engine.pass(consented(), 6_000);
    assert_eq!(at.counters.header_reads, 1, "{at:?}");
    assert_eq!(at.failure, Some(FailureCode::SourceIdle));
    assert_eq!(
        retry_row(&data)?,
        (2, Some(16_000), Some("source_idle".to_owned()))
    );
    assert_eq!(observed.metrics().header_reads, 1);

    // Busy: an exclusive writer lock, bounded by the SQLite busy timeout.
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let database = source.join("opencode.db");
    let mut writer = start_writer(&database)?;
    let engine = open_engine(&source, &data, &home)?;
    writer.command("exclusive", "LOCKED")?;
    let (mut engine, busy) = {
        let (engine, report) = pass_within(engine, 10_000, 5)?;
        (engine, report)
    };
    assert_eq!(
        (busy.outcome, busy.failure),
        (PassOutcome::Unavailable, Some(FailureCode::Busy))
    );
    assert_eq!(
        retry_row(&data)?,
        (1, Some(15_000), Some("busy".to_owned()))
    );
    writer.command("release", "RELEASED")?;
    // Leaving exclusive locking mode takes effect with the writer's next transaction.
    writer.exec("INSERT INTO records VALUES ('after-busy')")?;
    let gated = engine.pass(consented(), 14_999);
    assert_eq!(
        (gated.failure, gated.counters),
        (Some(FailureCode::Busy), Default::default())
    );
    // Released and past the deadline: the pass reads, resets the schedule and publishes.
    let read = engine.pass(consented(), 15_000);
    assert!(read.counters.source_opens > 0, "{read:?}");
    assert_ne!(read.outcome, PassOutcome::Unavailable, "{read:?}");
    assert_eq!(
        retry_row(&data)?,
        (0, None, None),
        "a stable read clears the schedule"
    );
    writer.stop()?;
    Ok(())
}

/// Event count, (value, conflict) of what each root observes, and each root's record count.
type CrossRootView = (i64, Vec<(Option<u64>, bool)>, [u64; 2]);

#[test]
fn two_registered_roots_share_one_history_with_a_deterministic_owner_in_either_arrival_order()
-> TestResult {
    let _guard = vfs_test_guard();
    for (name, a_input, b_input) in [("identical", 7_u64, 7_u64), ("divergent", 7, 9)] {
        let mut outcomes = Vec::new();
        for b_first in [false, true] {
            let directory = tempdir()?;
            let base = directory.path().canonicalize()?;
            let (home, data) = (base.join("home"), base.join("data"));
            std::fs::create_dir(&home)?;
            let (a, b) = (base.join("root-a"), base.join("root-b"));
            for (root, input) in [(&a, a_input), (&b, b_input)] {
                std::fs::create_dir(root)?;
                write_json_message(
                    root,
                    "sj",
                    "same",
                    T0,
                    Some(counts(
                        Some(input),
                        Some(0),
                        Some(0),
                        Some(0),
                        Some(0),
                        None,
                    )),
                )?;
            }
            let mut engine_a = open_engine(&a, &data, &home)?;
            let mut engine_b = open_engine(&b, &data, &home)?;
            let order: [bool; 2] = if b_first {
                [true, false]
            } else {
                [false, true]
            };
            for pass_b in order {
                let reports = if pass_b {
                    run_until_consistent(&mut engine_b, 1, 5)
                } else {
                    run_until_consistent(&mut engine_a, 1, 5)
                };
                assert_eq!(
                    reports.last().ok_or("pass")?.outcome,
                    PassOutcome::Consistent,
                    "{name}"
                );
            }
            let view = |engine_a: &quotern_core::ingest::OpenCodeEngine<_>,
                        engine_b: &quotern_core::ingest::OpenCodeEngine<_>|
             -> TestResult<CrossRootView> {
                let events: i64 = scalar(&data, "SELECT COUNT(*) FROM usage_events")?;
                let observed: Vec<_> = [engine_a, engine_b]
                    .into_iter()
                    .flat_map(|engine| engine.observations().expect("page"))
                    .map(|record| (record.input.value, record.mirror_conflict))
                    .collect();
                let report = PassReport::unavailable(FailureCode::Store, Default::default());
                Ok((
                    events,
                    observed,
                    [
                        engine_a.snapshot(&report)?.projection.records,
                        engine_b.snapshot(&report)?.projection.records,
                    ],
                ))
            };
            let seen = view(&engine_a, &engine_b)?;
            assert_eq!(seen.0, 1, "{name}: one event for the shared record id");
            assert_eq!(
                seen.2,
                [1, 0],
                "{name}: root-a owns it (UTF-8 byte order of root and path)"
            );
            assert_eq!(
                seen.1,
                vec![(Some(a_input), a_input != b_input)],
                "{name}: the owner's value, flagged only when the mirrors diverge"
            );
            // A reopen of both engines changes nothing.
            drop((engine_a, engine_b));
            let engine_a = open_engine(&a, &data, &home)?;
            let engine_b = open_engine(&b, &data, &home)?;
            assert_eq!(view(&engine_a, &engine_b)?, seen, "{name}: reopen");
            outcomes.push(seen);
        }
        assert_eq!(
            outcomes[0], outcomes[1],
            "{name}: arrival order does not matter"
        );
    }
    Ok(())
}

#[test]
fn every_sidecar_identity_change_during_acquisition_publishes_nothing_and_backs_off() -> TestResult
{
    use quotern_core::ingest::fs::OpenKind;
    let _guard = vfs_test_guard();
    // (sidecar suffix that appears or is replaced right before SQLite opens the database)
    for suffix in ["-journal", "-wal", "-shm"] {
        let directory = tempdir()?;
        let (source, data, home) = source_roots(directory.path())?;
        let database = source.join("opencode.db");
        let c = open_fixture(&database)?;
        put_message(
            &c,
            "m",
            "s",
            T0,
            &json!({"role": "assistant", "tokens": counts(Some(5), None, None, None, None, None)}),
        )?;
        drop(c);
        let fs = RecordingFs::new();
        let armed = Arc::new(AtomicBool::new(false));
        let (flag, sidecar) = (
            Arc::clone(&armed),
            PathBuf::from(format!("{}{suffix}", database.display())),
        );
        fs.on_boundary(move |kind, _| {
            if kind == OpenKind::Sqlite && flag.load(Ordering::SeqCst) {
                // An empty regular file: a new inode in the identity set between preflight and read.
                std::fs::write(&sidecar, b"").expect("sidecar appears");
            }
        });
        let observed = fs.clone();
        let mut engine = open_recording_engine(fs, &source, &data, &home)
            .map_err(|report| format!("OpenCode engine failed: {report:?}"))?;
        let baseline = engine.pass(consented(), 1);
        assert_eq!(baseline.outcome, PassOutcome::Consistent, "{baseline:?}");
        assert_eq!(engine.observations()?.len(), 1);
        c_update(&database, 6)?;
        armed.store(true, Ordering::SeqCst);
        let changed = engine.pass(consented(), 100);
        armed.store(false, Ordering::SeqCst);
        let label = format!("{suffix}: {changed:?}");
        assert_eq!(
            changed.failure,
            Some(FailureCode::SourceChanging),
            "{label}"
        );
        assert_ne!(changed.outcome, PassOutcome::Consistent, "{label}");
        let records = engine.observations()?;
        assert_eq!(
            find(&records, "m").input.value,
            Some(5),
            "{label}: history retained, nothing published"
        );
        assert!(find(&records, "m").pending_partial, "{label}");
        let (count, next, reason) = retry_row(&data)?;
        assert_eq!(
            (count, next, reason.as_deref()),
            (1, Some(5_100), Some("source_changing")),
            "{label}"
        );
        // At deadline - 1 nothing is read; after the sidecar settles and the deadline passes the
        // new value is published and the schedule resets.
        let before = observed.metrics();
        let gated = engine.pass(consented(), 5_099);
        assert_eq!(observed.metrics(), before, "{label}: no physical work");
        assert_eq!(gated.failure, Some(FailureCode::SourceChanging));
        let _ = std::fs::remove_file(format!("{}{suffix}", database.display()));
        let settled = run_until_consistent(&mut engine, 5_100, 4);
        assert_eq!(
            settled.last().ok_or("pass")?.outcome,
            PassOutcome::Consistent,
            "{label}: {settled:?}"
        );
        assert_eq!(
            find(&engine.observations()?, "m").input.value,
            Some(6),
            "{label}"
        );
        assert_eq!(retry_row(&data)?, (0, None, None), "{label}");
    }
    Ok(())
}

fn c_update(database: &Path, input: u64) -> TestResult {
    let c = Connection::open(database)?;
    c.execute(
        "UPDATE message SET data = ?1 WHERE id = 'm'",
        [serde_json::to_vec(&json!({"role": "assistant", "tokens": counts(Some(input), None, None, None, None, None)}))?],
    )?;
    Ok(())
}

/// Raw payload bytes at the decoder's real boundaries. The parser is serde_json with its default
/// recursion limit of 128, which admits 127 nesting levels counting the top-level object: 126
/// nested arrays below it parse, 127 do not. Records are at most 262,144 bytes.
fn raw_payload_cases(head: &str, prefix: &str) -> Vec<(String, Vec<u8>, Option<FailureCode>)> {
    let wrap = |inner: &str| format!("{{{head}{prefix},\"tokens\":{{\"input\":5}},\"x\":{inner}}}");
    let nested = |levels: usize| format!("{}{}", "[".repeat(levels), "]".repeat(levels));
    let sized = |length: usize| {
        let shell = format!("{{{head}{prefix},\"tokens\":{{\"input\":5}},\"x\":\"\"}}");
        let filler = "y".repeat(length - shell.len());
        shell
            .replace("\"x\":\"\"", &format!("\"x\":\"{filler}\""))
            .into_bytes()
    };
    let mut invalid_utf8 = wrap("\"z\"").into_bytes();
    let at = invalid_utf8
        .iter()
        .position(|byte| *byte == b'z')
        .expect("marker");
    invalid_utf8[at] = 0xff;
    vec![
        ("valid".to_owned(), wrap("1").into_bytes(), None),
        (
            "malformed syntax".to_owned(),
            format!("{{{head},").into_bytes(),
            Some(FailureCode::InvalidRecord),
        ),
        (
            "invalid utf-8".to_owned(),
            invalid_utf8,
            Some(FailureCode::InvalidRecord),
        ),
        (
            "nesting 127 levels".to_owned(),
            wrap(&nested(126)).into_bytes(),
            None,
        ),
        (
            "nesting 128 levels".to_owned(),
            wrap(&nested(127)).into_bytes(),
            Some(FailureCode::InvalidRecord),
        ),
        ("262,144 bytes".to_owned(), sized(262_144), None),
        (
            "262,145 bytes".to_owned(),
            sized(262_145),
            Some(FailureCode::RecordTooLarge),
        ),
    ]
}

#[test]
fn raw_json_files_malformed_nested_or_oversized_are_rejected_without_hurting_valid_neighbors()
-> TestResult {
    let _guard = vfs_test_guard();
    for (name, bytes, expected) in raw_payload_cases(
        "\"role\":\"assistant\"",
        ",\"time\":{\"created\":1700000000000}",
    ) {
        let directory = tempdir()?;
        let (source, data, home) = source_roots(directory.path())?;
        write_json_message(
            &source,
            "sj",
            "ok",
            T0,
            Some(counts(Some(1), None, None, None, None, None)),
        )?;
        let target = source.join("storage/message/sj/target.json");
        std::fs::write(&target, &bytes)?;
        let before = file_tree_image(&source)?;
        let mut engine = open_engine(&source, &data, &home)?;
        let first = engine.pass(consented(), 1);
        let records = engine.observations()?;
        assert_eq!(
            find(&records, "ok").input.value,
            Some(1),
            "{name}: the neighbor is unaffected"
        );
        match expected {
            None => {
                assert_eq!(first.outcome, PassOutcome::Consistent, "{name}: {first:?}");
                assert_eq!(find(&records, "target").input.value, Some(5), "{name}");
            }
            Some(code) => {
                assert_eq!(
                    (first.outcome, first.failure),
                    (PassOutcome::Partial, Some(code)),
                    "{name}: {first:?}"
                );
                assert_eq!(first.counters.rejected_records, 1, "{name}");
                assert!(
                    records.iter().all(|record| record.message_id != "target"),
                    "{name}"
                );
                assert_eq!(engine.snapshot(&first)?.projection.records, 1, "{name}");
            }
        }
        assert_eq!(
            file_tree_image(&source)?,
            before,
            "{name}: source unchanged"
        );
    }
    // The same bytes as a part file: a bad step-finish part leaves its group pending, never
    // partly summed; a valid part beside it is still read.
    for (name, bytes, expected) in raw_payload_cases("\"type\":\"step-finish\"", "") {
        let directory = tempdir()?;
        let (source, data, home) = source_roots(directory.path())?;
        write_json_message(
            &source,
            "sj",
            "m",
            T0,
            Some(counts(Some(1), None, None, None, None, None)),
        )?;
        write_json_part(
            &source,
            "m",
            "p1",
            &step_finish(counts(Some(40), Some(0), Some(0), Some(0), Some(0), None)),
        )?;
        let target = source.join("storage/part/m/p2.json");
        std::fs::write(&target, &bytes)?;
        let before = file_tree_image(&source)?;
        let mut engine = open_engine(&source, &data, &home)?;
        let first = engine.pass(consented(), 1);
        let records = engine.observations()?;
        match expected {
            None => {
                assert_eq!(
                    first.outcome,
                    PassOutcome::Consistent,
                    "part {name}: {first:?}"
                );
                assert_eq!(
                    find(&records, "m").input.value,
                    Some(45),
                    "part {name}: both parts summed"
                );
            }
            Some(code) => {
                assert_eq!(
                    first.outcome,
                    PassOutcome::Partial,
                    "part {name}: {first:?}"
                );
                assert!(
                    first.failure.is_some_and(
                        |failure| failure == code || failure == FailureCode::InvalidRecord
                    ),
                    "part {name}: {first:?}"
                );
                // Never summed from the readable part alone as if it were the whole group.
                assert!(
                    records
                        .iter()
                        .all(|record| record.input.value != Some(40) || record.pending_partial),
                    "part {name}: a half group was published as complete"
                );
            }
        }
        assert_eq!(
            file_tree_image(&source)?,
            before,
            "part {name}: source unchanged"
        );
    }
    Ok(())
}

#[test]
fn raw_sqlite_payloads_malformed_nested_or_oversized_are_rejected_in_both_layouts() -> TestResult {
    let _guard = vfs_test_guard();
    for layout in ["legacy", "v2"] {
        for (name, bytes, expected) in raw_payload_cases("\"role\":\"assistant\"", "") {
            let directory = tempdir()?;
            let (source, data, home) = source_roots(directory.path())?;
            let database = source.join("opencode.db");
            let c = open_fixture(&database)?;
            let ok = json!({"role": "assistant", "tokens": counts(Some(1), None, None, None, None, None)});
            if layout == "legacy" {
                put_message(&c, "ok", "s", T0, &ok)?;
                c.execute(
                    "INSERT INTO message(id, session_id, time_created, data) VALUES ('target', 's', ?1, ?2)",
                    rusqlite::params![T0, bytes],
                )?;
            } else {
                put_v2(&c, "ok", "s2", "assistant", 1, T0, &ok)?;
                c.execute(
                    "INSERT INTO session_message(id, session_id, type, seq, time_created, data) VALUES ('target', 's2', 'assistant', 2, ?1, ?2)",
                    rusqlite::params![T0, bytes],
                )?;
            }
            drop(c);
            let before = source_image(&database)?;
            let mut engine = open_engine(&source, &data, &home)?;
            let first = engine.pass(consented(), 1);
            let records = engine.observations()?;
            let label = format!("{layout} {name}");
            assert_eq!(find(&records, "ok").input.value, Some(1), "{label}");
            match expected {
                None => {
                    assert_eq!(first.outcome, PassOutcome::Consistent, "{label}: {first:?}");
                    assert_eq!(find(&records, "target").input.value, Some(5), "{label}");
                }
                Some(code) => {
                    assert_eq!(
                        (first.outcome, first.failure),
                        (PassOutcome::Partial, Some(code)),
                        "{label}: {first:?}"
                    );
                    assert_eq!(first.counters.rejected_records, 1, "{label}");
                    assert!(
                        records.iter().all(|record| record.message_id != "target"),
                        "{label}"
                    );
                    // Not a falsely clean terminal cursor: the failure stays sticky for the sweep.
                    assert_ne!(first.outcome, PassOutcome::Consistent, "{label}");
                }
            }
            assert_source_unchanged(&database, &before)?;
        }
    }
    Ok(())
}

#[test]
fn history_pages_and_known_paths_seek_their_indexes_with_work_independent_of_history_size()
-> TestResult {
    use quotern_core::store::{Store, history_page_sql, known_paths_sql};
    let _guard = vfs_test_guard();
    let build = |events: i64| -> TestResult<(tempfile::TempDir, Connection)> {
        let directory = tempdir()?;
        let data = directory.path().join("data");
        let mut store = Store::open(&data)?;
        store.register_source(
            directory.path(),
            quotern_core::domain::SourceKind::Custom,
            (1, 1),
        )?;
        drop(store);
        let c = Connection::open(data.join("history.sqlite"))?;
        let source: String = c.query_row("SELECT source_id FROM sources", [], |row| row.get(0))?;
        let tx = c.unchecked_transaction()?;
        for index in 0..events {
            tx.execute(
                "INSERT INTO usage_events(event_key, family, measurement_kind, harness, source_id, session_id, message_id, \
                 occurred_at_ms, input_tokens, total_provenance, source_convention, acquisition_consistency, origin_uncertainty, \
                 total_mismatch, mirror_conflict, selected_part_ids, format_rank, mirror_path, revision, first_seen_ms, updated_ms) \
                 VALUES (?1, 'opencode', 'source_reported', 'opencode', ?2, 's', ?3, ?4, 1, NULL, NULL, 'sqlite_read_transaction', \
                 'unverified_origin', 0, 0, '[]', 0, 'p', 1, 0, 0)",
                rusqlite::params![format!("e{index:07}"), source, format!("m{index}"), 1_700_000_000_000_i64 + index / 3],
            )?;
            tx.execute(
                "INSERT INTO source_files(source_id, relative_path, device, inode, size, mtime_ns, byte_offset, first_line_fnv64, \
                 adapter_state, parse_generation, file_state, visit_seq) VALUES (?1, ?2, 1, ?3, 0, ?4, 0, 0, 'sqlite', 0, 'present', ?5)",
                rusqlite::params![source, format!("opencode-{index:07}.db"), index, index, index % 7],
            )?;
        }
        tx.commit()?;
        Ok((directory, c))
    };
    let (_small_dir, small) = build(1_000)?;
    let (_big_dir, big) = build(20_000)?;
    let late = |c: &Connection, events: i64| -> TestResult<(i32, String)> {
        let source: String = c.query_row("SELECT source_id FROM sources", [], |row| row.get(0))?;
        let key = format!("e{:07}", events - 12);
        let at = 1_700_000_000_000_i64 + (events - 12) / 3;
        let parameters: [&dyn rusqlite::ToSql; 4] = [&source, &11_i64, &at, &key];
        let steps = vm_steps(c, history_page_sql(true), &parameters)?;
        Ok((
            steps,
            plan(c, history_page_sql(true), &parameters)?.join(" | "),
        ))
    };
    let (small_steps, small_plan) = late(&small, 1_000)?;
    let (big_steps, big_plan) = late(&big, 20_000)?;
    for plan in [&small_plan, &big_plan] {
        assert!(plan.contains("usage_events_source"), "{plan}");
        assert!(!plan.contains("TEMP B-TREE"), "{plan}");
    }
    assert!(
        big_steps <= small_steps + small_steps / 4 + 50,
        "a late page costs {big_steps} steps over 20,000 events but {small_steps} over 1,000"
    );
    let source: String = big.query_row("SELECT source_id FROM sources", [], |row| row.get(0))?;
    let first: [&dyn rusqlite::ToSql; 2] = [&source, &11_i64];
    let first_plan = plan(&big, history_page_sql(false), &first)?.join(" | ");
    assert!(
        first_plan.contains("usage_events_source") && !first_plan.contains("TEMP B-TREE"),
        "{first_plan}"
    );
    // The exact order and boundary of a page: the eleven rows after the cursor, in tuple order.
    let cursor_key = format!("e{:07}", 19_988);
    let cursor_at = 1_700_000_000_000_i64 + 19_988 / 3;
    let mut statement = big.prepare(history_page_sql(true))?;
    let keys: Vec<String> = statement
        .query_map(
            rusqlite::params![source, 11_i64, cursor_at, cursor_key],
            |row| row.get(0),
        )?
        .collect::<Result<_, _>>()?;
    assert_eq!(
        keys,
        (19_989..20_000)
            .map(|index| format!("e{index:07}"))
            .collect::<Vec<_>>()
    );

    // Known paths: the indexed rotating order, bounded work whatever the history size.
    let known = |c: &Connection| -> TestResult<(i32, String)> {
        let source: String = c.query_row("SELECT source_id FROM sources", [], |row| row.get(0))?;
        let parameters: [&dyn rusqlite::ToSql; 3] = [&source, &"sqlite", &100_i64];
        Ok((
            vm_steps(c, known_paths_sql(), &parameters)?,
            plan(c, known_paths_sql(), &parameters)?.join(" | "),
        ))
    };
    let (small_known, small_known_plan) = known(&small)?;
    let (big_known, big_known_plan) = known(&big)?;
    for plan in [&small_known_plan, &big_known_plan] {
        assert!(plan.contains("source_files_known"), "{plan}");
        assert!(!plan.contains("TEMP B-TREE"), "{plan}");
    }
    assert!(
        big_known <= small_known + small_known / 4 + 50,
        "{big_known} vs {small_known}"
    );
    Ok(())
}

#[test]
fn the_maintained_projection_equals_an_independent_recount_through_revisions_and_reassignment()
-> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let base = directory.path().canonicalize()?;
    let (home, data) = (base.join("home"), base.join("data"));
    std::fs::create_dir(&home)?;
    let (a, b) = (base.join("root-a"), base.join("root-b"));
    for root in [&a, &b] {
        std::fs::create_dir(root)?;
    }
    // root-b has the record first (it owns it); root-a arrives later and takes ownership; a
    // revision of an unrelated record and an absent aggregate exercise every column.
    write_json_message(
        &b,
        "sj",
        "shared",
        T0,
        Some(counts(Some(9), Some(1), None, None, None, None)),
    )?;
    write_json_message(
        &b,
        "sj",
        "only-b",
        T0 + 1,
        Some(counts(Some(3), Some(0), Some(0), Some(0), Some(0), Some(3))),
    )?;
    let mut engine_b = open_engine(&b, &data, &home)?;
    run_until_consistent(&mut engine_b, 1, 5);
    write_json_message(
        &a,
        "sj",
        "shared",
        T0,
        Some(counts(Some(7), Some(1), Some(0), Some(0), Some(0), None)),
    )?;
    let mut engine_a = open_engine(&a, &data, &home)?;
    run_until_consistent(&mut engine_a, 1, 5);
    write_json_message(
        &b,
        "sj",
        "only-b",
        T0 + 1,
        Some(counts(Some(4), Some(0), Some(0), Some(0), Some(0), Some(4))),
    )?;
    run_until_consistent(&mut engine_b, 1_000_000, 5);
    let report = PassReport::unavailable(FailureCode::Store, Default::default());
    type Recount = (i64, Option<i64>, i64, Option<i64>, i64, Option<i64>, i64);
    let recount = |source_id: &str| -> TestResult<Recount> {
        Ok(history(&data)?.query_row(
            "SELECT COUNT(*), SUM(input_tokens), COUNT(input_tokens), SUM(output_tokens), COUNT(total_tokens), \
             SUM(total_tokens), COALESCE(SUM(total_provenance = 'derived'), 0) FROM usage_events WHERE source_id = ?1",
            [source_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
        )?)
    };
    for engine in [&engine_a, &engine_b] {
        let snapshot = engine.snapshot(&report)?;
        let (records, input, input_count, output, total_count, total, derived) =
            recount(&snapshot.source_id)?;
        let projection = snapshot.projection;
        assert_eq!(projection.records as i64, records);
        assert_eq!(projection.input.value.map(|value| value as i64), input);
        assert_eq!(projection.output.value.map(|value| value as i64), output);
        assert_eq!(projection.total.value.map(|value| value as i64), total);
        assert_eq!(
            projection.input.status == ObservationStatus::Current,
            input_count == records && records > 0
        );
        assert_eq!(
            projection.total.status == ObservationStatus::Current,
            total_count == records && records > 0
        );
        assert_eq!(
            projection.source_convention.is_some(),
            derived > 0 && total_count > 0
        );
    }
    let (a_owned, b_owned) = (
        engine_a.snapshot(&report)?.projection.records,
        engine_b.snapshot(&report)?.projection.records,
    );
    assert_eq!(
        (a_owned, b_owned),
        (1, 1),
        "root-a took the shared record; root-b kept only-b"
    );
    // The revision of only-b reached the maintained numbers exactly once.
    assert_eq!(engine_b.snapshot(&report)?.projection.input.value, Some(4));
    Ok(())
}

#[test]
fn iterator_errors_and_every_physical_metadata_operation_are_charged_to_the_pass() -> TestResult {
    use quotern_core::ingest::fs::{DirEntries, SourceFs, physical_operations};
    /// Yields one error before the real entries, as a failing `readdir` would.
    #[derive(Clone, Copy)]
    struct FailingListing;
    impl SourceFs for FailingListing {
        fn canonicalize(
            &self,
            path: &Path,
            c: &mut quotern_core::domain::PassCounters,
        ) -> std::io::Result<PathBuf> {
            quotern_core::ingest::fs::RealSourceFs.canonicalize(path, c)
        }
        fn metadata(
            &self,
            path: &Path,
            c: &mut quotern_core::domain::PassCounters,
        ) -> std::io::Result<std::fs::Metadata> {
            quotern_core::ingest::fs::RealSourceFs.metadata(path, c)
        }
        fn read_dir(
            &self,
            path: &Path,
            c: &mut quotern_core::domain::PassCounters,
        ) -> std::io::Result<DirEntries> {
            let real = quotern_core::ingest::fs::RealSourceFs.read_dir(path, c)?;
            Ok(Box::new(
                std::iter::once(Err(std::io::Error::other("injected readdir failure"))).chain(real),
            ))
        }
        fn read_header(
            &self,
            path: &Path,
            c: &mut quotern_core::domain::PassCounters,
        ) -> std::io::Result<Vec<u8>> {
            quotern_core::ingest::fs::RealSourceFs.read_header(path, c)
        }
        fn read_bounded(
            &self,
            path: &Path,
            max: usize,
            c: &mut quotern_core::domain::PassCounters,
        ) -> std::io::Result<quotern_core::ingest::fs::BoundedRead> {
            quotern_core::ingest::fs::RealSourceFs.read_bounded(path, max, c)
        }
        fn open_sqlite(
            &self,
            path: &Path,
        ) -> Result<Connection, quotern_core::ingest::sqlite_ro::OpenError> {
            quotern_core::ingest::fs::RealSourceFs.open_sqlite(path)
        }
    }
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    write_json_message(
        &source,
        "sj",
        "m",
        T0,
        Some(counts(Some(1), None, None, None, None, None)),
    )?;
    let mut engine = quotern_core::ingest::OpenCodeEngine::open(
        FailingListing,
        &source,
        &data,
        &home,
        quotern_core::domain::SourceAuthorization {
            selected: true,
            consent: quotern_core::domain::ConsentState::Enabled,
        },
        quotern_core::domain::SourceKind::Custom,
    )
    .map_err(|report| format!("open failed: {report:?}"))?;
    let report = engine.pass(consented(), 1);
    // Every directory listing yields exactly one error: it is an entry, not free work.
    assert!(report.counters.entries >= 1, "{report:?}");
    assert_eq!(report.failure, Some(FailureCode::Io), "{report:?}");
    // The engine's reported metadata calls equal the operations physically performed.
    let (real_dir, real_data, real_home) = {
        let d = tempdir()?;
        let (s, da, h) = source_roots(d.path())?;
        write_json_message(
            &s,
            "sj",
            "m",
            T0,
            Some(counts(Some(1), Some(1), Some(1), Some(1), Some(1), None)),
        )?;
        write_json_part(
            &s,
            "m",
            "p1",
            &step_finish(counts(Some(1), Some(1), Some(1), Some(1), Some(1), None)),
        )?;
        (d, (s, da), h)
    };
    let mut engine = open_engine(&real_data.0, &real_data.1, &real_home)?;
    let before = physical_operations();
    let report = engine.pass(consented(), 1);
    let physical = physical_operations().metadata - before.metadata;
    assert_eq!(
        u64::from(report.counters.stat_calls),
        physical,
        "{report:?}"
    );
    drop(real_dir);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Third-fold regressions: at-open swaps, creation interruption, wire/durable/cursor/algebra
// boundaries, changed-group witness, many-database drain
// ---------------------------------------------------------------------------------------------

#[test]
fn source_database_swapped_at_the_instant_of_open_is_refused_not_read_or_waited_on() -> TestResult {
    use quotern_core::ingest::sqlite_ro::set_open_hook;
    let _guard = vfs_test_guard();
    for mode in ["other-database", "fifo"] {
        let (done, result) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let outcome = (|| -> TestResult<(PassOutcome, u64, Option<u64>, bool)> {
                let directory = tempdir()?;
                let (source, data, home) = source_roots(&directory.path().canonicalize()?)?;
                let target = source.join("opencode.db");
                drop(bulk_legacy(&target, 1, 10)?);
                let outside = directory.path().canonicalize()?.join("outside.db");
                drop(bulk_legacy(&outside, 1, 999)?);
                let outside_bytes = std::fs::read(&outside)?;
                let parked = directory.path().canonicalize()?.join("parked.db");
                let (hook_target, hook_outside) = (target.clone(), outside.clone());
                let fired = std::cell::Cell::new(false);
                set_open_hook(Some(Box::new(move |path| {
                    if path == hook_target && !fired.replace(true) {
                        std::fs::rename(&hook_target, &parked).expect("park the database");
                        if mode == "fifo" {
                            let made = std::process::Command::new("mkfifo")
                                .arg(&hook_target)
                                .status()
                                .expect("mkfifo");
                            assert!(made.success());
                        } else {
                            std::fs::rename(&hook_outside, &hook_target).expect("swap in");
                        }
                    }
                })));
                let mut engine = open_engine(&source, &data, &home)?;
                let report = engine.pass(consented(), 1);
                set_open_hook(None);
                let projection = engine.snapshot(&report)?.projection;
                let untouched = mode == "fifo" || std::fs::read(&target)? == outside_bytes;
                Ok((
                    report.outcome,
                    projection.records,
                    projection.input.value,
                    untouched,
                ))
            })();
            let _ = done.send(outcome.map_err(|error| error.to_string()));
        });
        let (outcome, records, input, untouched) =
            result
                .recv_timeout(Duration::from_secs(60))
                .map_err(|_| format!("{mode}: the pass blocked on the swapped path"))??;
        assert_ne!(outcome, PassOutcome::Consistent, "{mode}");
        assert_eq!(
            records, 0,
            "{mode}: nothing from the swapped inode is published"
        );
        assert_ne!(input, Some(999), "{mode}");
        assert!(untouched, "{mode}: the outside database is never modified");
    }
    Ok(())
}

#[test]
fn store_database_swapped_at_the_instant_of_open_is_refused_before_any_write() -> TestResult {
    use quotern_core::ingest::sqlite_ro::set_open_hook;
    use quotern_core::store::{Store, StoreError};
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let base = directory.path().canonicalize()?;
    let data = base.join("data");
    drop(Store::open(&data)?);
    let external = base.join("external.db");
    drop(bulk_legacy(&external, 1, 1)?);
    let external_bytes = std::fs::read(&external)?;
    let database = data.join("history.sqlite");
    let parked = base.join("parked.sqlite");
    let (hook_database, hook_external) = (database.clone(), external.clone());
    let seen = std::cell::Cell::new(0_u32);
    // The first by-name open of the store is the read-only admission view; the second is the
    // writable open, which is where the path becomes a hard-link alias of an external file.
    set_open_hook(Some(Box::new(move |path| {
        if path == hook_database {
            seen.set(seen.get() + 1);
            if seen.get() == 2 {
                std::fs::rename(&hook_database, &parked).expect("park");
                std::fs::hard_link(&hook_external, &hook_database).expect("alias");
            }
        }
    })));
    let result = Store::open(&data);
    set_open_hook(None);
    assert_eq!(result.err(), Some(StoreError::UnsafeFile));
    assert_eq!(
        std::fs::read(&external)?,
        external_bytes,
        "the aliased external file is never written"
    );
    Ok(())
}

#[test]
fn fresh_store_creation_interrupted_before_commit_is_empty_and_restarts_cleanly() -> TestResult {
    use quotern_core::store::{Store, StoreError};
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let data = directory.path().join("data");
    quotern_core::store::migrations::interrupt_next_creation();
    assert_eq!(Store::open(&data).err(), Some(StoreError::Sqlite));
    {
        let c = Connection::open(data.join("history.sqlite"))?;
        let objects: i64 = c.query_row("SELECT COUNT(*) FROM sqlite_master", [], |r| r.get(0))?;
        let version: i64 = c.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        assert_eq!((objects, version), (0, 0), "empty after the interruption");
    }
    drop(Store::open(&data)?);
    let shape = |data: &Path| -> TestResult<(i64, i64)> {
        let c = history(data)?;
        Ok((
            c.query_row("SELECT COUNT(*) FROM sqlite_master", [], |r| r.get(0))?,
            c.query_row("PRAGMA user_version", [], |r| r.get(0))?,
        ))
    };
    let complete = shape(&data)?;
    assert!(complete.0 > 0 && complete.1 == 1, "{complete:?}");
    drop(Store::open(&data)?);
    assert_eq!(
        shape(&data)?,
        complete,
        "a compatible reopen changes nothing"
    );
    Ok(())
}

/// Version and object names of a store database, read with plain SQL (never through the
/// production schema code, so a wrong creation cannot vouch for itself).
fn schema_state(connection: &Connection) -> TestResult<(i64, Vec<(String, String)>)> {
    let version = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let mut statement = connection.prepare(
        "SELECT type, name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
    )?;
    let objects = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<Vec<(String, String)>>>()?;
    Ok((version, objects))
}

/// The complete v1 object set, written out literally.
fn complete_v1_objects() -> Vec<(String, String)> {
    let indexes = [
        "reported_groups_event",
        "reported_groups_path",
        "source_files_known",
        "usage_events_occurred_at",
        "usage_events_source",
    ]
    .map(|name| ("index".to_owned(), name.to_owned()));
    let tables = [
        "acquisition_failures",
        "frontier_directories",
        "group_baseline",
        "metadata_spool",
        "opencode_candidate_spool",
        "opencode_progress",
        "reported_groups",
        "source_files",
        "source_projection_totals",
        "source_status",
        "sources",
        "usage_events",
    ]
    .map(|name| ("table".to_owned(), name.to_owned()));
    indexes.into_iter().chain(tables).collect()
}

/// A complete, internally consistent store: exact version and objects, intact pages and no
/// dangling reference.
fn assert_complete_store(data: &Path) -> TestResult {
    let connection = history(data)?;
    assert_eq!(schema_state(&connection)?, (1, complete_v1_objects()));
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    assert_eq!(integrity, "ok");
    let violations = connection
        .prepare("PRAGMA foreign_key_check")?
        .query_map([], |row| row.get::<_, String>(0))?
        .count();
    assert_eq!(violations, 0, "foreign_key_check rows");
    Ok(())
}

/// Encoded-consumer oracle of the fresh-schema fixture: one SQLite message whose total is derived
/// from its five components plus one JSON message with an explicit total that disagrees with its
/// components. Every expected number is written here, never taken from the producer.
fn assert_fresh_v1_consumers<F: quotern_core::ingest::fs::SourceFs>(
    engine: &OpenCodeEngine<F>,
    report: &PassReport,
    data: &Path,
    source: &Path,
) -> TestResult {
    use quotern_core::snapshot::{ObservationPage, SourceSnapshot};
    let encoded_snapshot = serde_json::to_vec(&engine.snapshot(report)?)?;
    let snapshot = SourceSnapshot::decode(&encoded_snapshot)?;
    // The envelope (outcome, failure, identity, freshness, counters) is compared with literals,
    // with the actual report and with the durable rows read by plain SQL, never with itself.
    type Status = (String, Option<String>, Option<i64>, [i64; 8]);
    let (durable_id, root, sources): (String, String, i64) = history(data)?.query_row(
        "SELECT source_id, canonical_root, (SELECT COUNT(*) FROM sources) FROM sources",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(sources, 1, "one durable source");
    assert_eq!(Path::new(&root), source.canonicalize()?);
    let status: Status = history(data)?.query_row(
        "SELECT outcome, last_error_code, last_success_ms, entry_count, stat_count, \
         header_count, directory_count, source_open_count, row_count, bytes_count, \
         rejected_count FROM source_status WHERE source_id = ?1",
        [&durable_id],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                [
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                ],
            ))
        },
    )?;
    assert_eq!(snapshot.source_id, durable_id, "durable source identity");
    assert_eq!(
        (snapshot.outcome, snapshot.failure),
        (PassOutcome::Consistent, None)
    );
    assert_eq!((status.0.as_str(), &status.1), ("consistent", &None));
    assert!(status.2.is_some(), "{status:?}");
    assert_eq!(snapshot.last_good_ms, status.2, "durable last success");
    assert_eq!(snapshot.last_good_ms, report.last_good_ms, "actual report");
    assert_eq!(snapshot.counters, report.counters, "counters round-trip");
    let envelope: Value = serde_json::from_slice(&encoded_snapshot)?;
    assert_eq!(envelope["source_id"], json!(durable_id));
    assert_eq!(envelope["outcome"], json!("consistent"));
    assert_eq!(envelope["failure"], Value::Null);
    assert_eq!(envelope["last_good_ms"], json!(status.2));
    assert_eq!(
        envelope["counters"],
        json!({
            "entries": status.3[0],
            "stat_calls": status.3[1],
            "header_reads": status.3[2],
            "directory_opens": status.3[3],
            "source_opens": status.3[4],
            "rows_read": status.3[5],
            "bytes_read": status.3[6],
            "rejected_records": status.3[7],
        }),
        "encoded counters are the durable pass counters"
    );
    let observed = |value: u64, provenance: &str| json!({"value": value, "unit": "tokens", "provenance": provenance, "status": "current"});
    assert_eq!(
        serde_json::to_value(&snapshot.projection)?,
        json!({
            "records": 2,
            "input": observed(11, "reported"),
            "output": observed(22, "reported"),
            "reasoning": observed(3, "reported"),
            "cache_read": observed(4, "reported"),
            "cache_write": observed(5, "reported"),
            "total": observed(141, "derived"),
            "source_convention": "codexbar-3239175f-disjoint",
            "acquisition_consistency": "mixed",
            "origin_uncertainty": "unverified_origin",
            "total_mismatch": true,
            "mirror_conflict": false,
            "pending_partial": false
        })
    );
    let first = ObservationPage::decode(&serde_json::to_vec(&engine.observations_page(None, 1)?)?)?;
    assert_eq!(first.observations.len(), 1);
    let cursor = first.next.as_ref().ok_or("missing first-page cursor")?;
    assert_eq!(
        (cursor.occurred_at_ms, cursor.record_id.as_str()),
        (T0, "opencode:1:s:7:derived")
    );
    let second = ObservationPage::decode(&serde_json::to_vec(
        &engine.observations_page(Some(cursor), 1)?,
    )?)?;
    assert_eq!(second.observations.len(), 1);
    assert_eq!(second.next, None);
    for (record, message, record_id, at, numbers, provenance, convention, acquisition, mismatch) in [
        (
            &first.observations[0],
            "derived",
            "opencode:1:s:7:derived",
            T0,
            [10, 20, 3, 4, 5, 42],
            "derived",
            Some("codexbar-3239175f-disjoint"),
            "sqlite_read_transaction",
            false,
        ),
        (
            &second.observations[0],
            "explicit",
            "opencode:1:s:8:explicit",
            T0 + 1,
            [1, 2, 0, 0, 0, 99],
            "reported",
            None,
            "file_by_file_best_effort",
            true,
        ),
    ] {
        assert_eq!(record.source_id, snapshot.source_id);
        assert_eq!(
            (
                record.session_id.as_str(),
                record.message_id.as_str(),
                record.record_id.as_str(),
                record.occurred_at_ms
            ),
            ("s", message, record_id, at)
        );
        assert_eq!(values(record), numbers.map(Some));
        let encoded = serde_json::to_value(record)?;
        for (field, number) in ["input", "output", "reasoning", "cache_read", "cache_write"]
            .into_iter()
            .zip(numbers)
        {
            assert_eq!(encoded[field], observed(number, "reported"));
        }
        assert_eq!(encoded["total"], observed(numbers[5], provenance));
        assert_eq!(encoded["source_convention"], json!(convention));
        assert_eq!(encoded["acquisition_consistency"], json!(acquisition));
        assert_eq!(encoded["origin_uncertainty"], json!("unverified_origin"));
        assert_eq!(encoded["total_mismatch"], json!(mismatch));
        assert_eq!(encoded["mirror_conflict"], json!(false));
        assert_eq!(encoded["pending_partial"], json!(false));
        assert_eq!(encoded["pending_reason"], Value::Null);
        assert_eq!(encoded["selected_part_ids"], json!([]));
        assert_eq!(encoded["revision"], json!(1));
    }
    assert_eq!(
        engine.observations()?,
        vec![
            first.observations[0].clone(),
            second.observations[0].clone()
        ]
    );
    Ok(())
}

/// The same fixture read straight from the durable store, with expected numbers written out.
fn assert_fresh_v1_durable(data: &Path, source: &Path, last_good: Option<i64>) -> TestResult {
    let connection = history(data)?;
    let sources: Vec<(String, String)> = connection
        .prepare("SELECT source_id, canonical_root FROM sources")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    assert_eq!(sources.len(), 1, "{sources:?}");
    assert_eq!(Path::new(&sources[0].1), source.canonicalize()?);
    let source_id = &sources[0].0;
    type Event = (
        String,
        String,
        i64,
        [Option<i64>; 6],
        Option<String>,
        Option<String>,
        String,
        i64,
        i64,
        String,
    );
    let events: Vec<Event> = connection
        .prepare(
            "SELECT event_key, message_id, occurred_at_ms, input_tokens, output_tokens, \
             reasoning_tokens, cache_read_tokens, cache_write_tokens, total_tokens, \
             total_provenance, source_convention, acquisition_consistency, total_mismatch, \
             revision, selected_part_ids FROM usage_events WHERE source_id = ?1 \
             ORDER BY occurred_at_ms, event_key",
        )?
        .query_map([source_id], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                [
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ],
                row.get(9)?,
                row.get(10)?,
                row.get(11)?,
                row.get(12)?,
                row.get(13)?,
                row.get(14)?,
            ))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let convention = Some("codexbar-3239175f-disjoint".to_owned());
    let expected: Vec<Event> = vec![
        (
            "opencode:1:s:7:derived".to_owned(),
            "derived".to_owned(),
            T0,
            [10, 20, 3, 4, 5, 42].map(Some),
            Some("derived".to_owned()),
            convention,
            "sqlite_read_transaction".to_owned(),
            0,
            1,
            "[]".to_owned(),
        ),
        (
            "opencode:1:s:8:explicit".to_owned(),
            "explicit".to_owned(),
            T0 + 1,
            [1, 2, 0, 0, 0, 99].map(Some),
            Some("reported".to_owned()),
            None,
            "file_by_file_best_effort".to_owned(),
            1,
            1,
            "[]".to_owned(),
        ),
    ];
    assert_eq!(events, expected);
    let totals: Vec<i64> = connection.query_row(
        "SELECT records, input_count, input_sum, output_count, output_sum, reasoning_count, \
         reasoning_sum, cache_read_count, cache_read_sum, cache_write_count, cache_write_sum, \
         total_count, total_sum, derived_total_count, mismatch_count, conflict_count, \
         pending_count, sqlite_count, json_count FROM source_projection_totals \
         WHERE source_id = ?1",
        [source_id],
        |row| (0..19).map(|index| row.get(index)).collect(),
    )?;
    assert_eq!(
        totals,
        [2, 2, 11, 2, 22, 2, 3, 2, 4, 2, 5, 2, 141, 1, 1, 0, 0, 1, 1]
    );
    let status: (String, Option<String>, Option<i64>) = connection.query_row(
        "SELECT outcome, last_error_code, last_success_ms FROM source_status \
         WHERE source_id = ?1",
        [source_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(status.0, "consistent");
    assert_eq!(status.1, None);
    assert!(status.2.is_some(), "{status:?}");
    if let Some(last_good) = last_good {
        assert_eq!(status.2, Some(last_good));
    }
    Ok(())
}

fn fresh_schema_protocol_close() -> TestResult {
    println!("READY");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    assert_eq!(line.trim(), "exit");
    println!("CLOSED");
    std::io::stdout().flush()?;
    Ok(())
}

/// Process role of the fresh-schema proof (fault, crash, retry, reopen). Without its environment
/// (an ordinary run) it does nothing and proves nothing; the driver below is the assertion.
#[test]
fn fresh_schema_child_entrypoint() -> TestResult {
    use quotern_core::store::{Store, StoreError};
    let Some(base) = std::env::var_os("QUOTERN_FRESH_SCHEMA_BASE") else {
        return Ok(());
    };
    let base = PathBuf::from(base);
    let mode = std::env::var("QUOTERN_FRESH_SCHEMA_MODE")?;
    let (source, data, home) = (base.join("source"), base.join("data"), base.join("home"));
    let saved = base.join("fresh-schema-report.json");
    match mode.as_str() {
        "fault" => {
            quotern_core::store::migrations::interrupt_next_creation();
            assert_eq!(Store::open(&data).err(), Some(StoreError::Sqlite));
            assert_eq!(schema_state(&history(&data)?)?, (0, Vec::new()));
        }
        "crash" => {
            quotern_core::store::migrations::set_creation_hook(Some(Box::new(|connection| {
                assert_eq!(
                    schema_state(connection).expect("transaction schema"),
                    (1, complete_v1_objects())
                );
                let journal: String = connection
                    .query_row("PRAGMA journal_mode", [], |row| row.get(0))
                    .expect("store journal mode");
                assert_eq!(journal, "wal");
                println!("SCHEMA_UNCOMMITTED");
                std::io::stdout().flush().expect("flush creation barrier");
                let mut line = String::new();
                std::io::stdin()
                    .read_line(&mut line)
                    .expect("creation barrier input");
                panic!("creation barrier released instead of child termination");
            })));
            let result = Store::open(&data);
            panic!("creation hook was not reached: {:?}", result.err());
        }
        "retry" => {
            let mut engine = open_engine(&source, &data, &home)?;
            assert_eq!(schema_state(&history(&data)?)?, (1, complete_v1_objects()));
            assert!(engine.observations()?.is_empty());
            let reports = run_until_consistent(&mut engine, T0 + 100, 6);
            let last = reports.last().ok_or("no pass ran")?;
            assert_eq!(
                (last.outcome, last.failure),
                (PassOutcome::Consistent, None),
                "{reports:?}"
            );
            assert!(last.last_good_ms.is_some(), "{last:?}");
            assert_fresh_v1_consumers(&engine, last, &data, &source)?;
            std::fs::write(&saved, serde_json::to_vec(last)?)?;
            drop(engine);
        }
        "reopen" => {
            let before: PassReport = serde_json::from_slice(&std::fs::read(&saved)?)?;
            let mut engine = open_engine(&source, &data, &home)?;
            // Before any pass: the retained history alone must already satisfy every oracle.
            assert_eq!(schema_state(&history(&data)?)?, (1, complete_v1_objects()));
            assert_fresh_v1_consumers(&engine, &before, &data, &source)?;
            assert_fresh_v1_durable(&data, &source, before.last_good_ms)?;
            let reports = run_until_consistent(&mut engine, T0 + 1_000, 6);
            let last = reports.last().ok_or("no pass ran")?;
            assert_eq!(
                (last.outcome, last.failure),
                (PassOutcome::Consistent, None),
                "{reports:?}"
            );
            assert_fresh_v1_consumers(&engine, last, &data, &source)?;
            std::fs::write(
                base.join("fresh-schema-report-reopen.json"),
                serde_json::to_vec(last)?,
            )?;
            drop(engine);
        }
        other => return Err(format!("unknown fresh-schema mode: {other}").into()),
    }
    fresh_schema_protocol_close()
}

/// A fresh store creation interrupted by a real fault, and by a real process kill while the
/// creation transaction is live, leaves no schema and no version; a new process then creates the
/// store, ingests, and a further new process reopens it with the retained history intact.
#[test]
fn fresh_v1_native_interruption_retry_history_and_encoded_consumer() -> TestResult {
    use std::ffi::OsStr;
    let _guard = vfs_test_guard();
    let spawn = |base: &Path, mode: &str, ready: &str| {
        WriterChild::spawn(
            "fresh_schema_child_entrypoint",
            &[
                ("QUOTERN_FRESH_SCHEMA_BASE", base.as_os_str()),
                ("QUOTERN_FRESH_SCHEMA_MODE", OsStr::new(mode)),
            ],
            ready,
        )
    };
    for interruption in ["fault", "crash"] {
        let directory = tempdir()?;
        let base = directory.path().canonicalize()?;
        let (source, data, _home) = source_roots(&base)?;
        let database = source.join("opencode.db");
        let seed = open_fixture(&database)?;
        put_message(
            &seed,
            "derived",
            "s",
            T0,
            &json!({"role": "assistant", "tokens": {
                "input": 10, "output": 20, "reasoning": 3, "cache": {"read": 4, "write": 5}
            }}),
        )?;
        drop(seed);
        write_json_message(
            &source,
            "s",
            "explicit",
            T0 + 1,
            Some(counts(
                Some(1),
                Some(2),
                Some(0),
                Some(0),
                Some(0),
                Some(99),
            )),
        )?;
        let json_path = source.join("storage/message/s/explicit.json");
        let (before_database, before_json, before_tree) = (
            source_image(&database)?,
            std::fs::read(&json_path)?,
            source_tree_stamps(&source)?,
        );
        let source_unchanged = || -> TestResult {
            assert_eq!(source_image(&database)?, before_database);
            assert_eq!(std::fs::read(&json_path)?, before_json);
            assert_eq!(source_tree_stamps(&source)?, before_tree);
            Ok(())
        };

        if interruption == "crash" {
            let mut child = spawn(&base, "crash", "SCHEMA_UNCOMMITTED")?;
            // The child's creation transaction holds the complete schema and version 1 while an
            // independent reader still sees the empty store.
            assert_eq!(schema_state(&history(&data)?)?, (0, Vec::new()));
            child.crash()?;
            // After the kill and before any retry process exists, an independent reader of the
            // surviving files finds no schema and version 0: the creation rolled back, so the
            // retry below recreates the store instead of admitting a surviving complete v1.
            assert_eq!(
                schema_state(&history(&data)?)?,
                (0, Vec::new()),
                "history after the creation transaction was killed"
            );
        } else {
            let mut child = spawn(&base, "fault", "READY")?;
            child.stop()?;
            assert_eq!(schema_state(&history(&data)?)?, (0, Vec::new()));
        }
        source_unchanged()?;

        let mut retry = spawn(&base, "retry", "READY")?;
        retry.stop()?;
        assert_complete_store(&data)?;
        let saved: PassReport =
            serde_json::from_slice(&std::fs::read(base.join("fresh-schema-report.json"))?)?;
        assert_eq!(saved.outcome, PassOutcome::Consistent);
        assert_fresh_v1_durable(&data, &source, saved.last_good_ms)?;
        source_unchanged()?;

        let mut reopen = spawn(&base, "reopen", "READY")?;
        reopen.stop()?;
        assert_complete_store(&data)?;
        let updated: PassReport = serde_json::from_slice(&std::fs::read(
            base.join("fresh-schema-report-reopen.json"),
        )?)?;
        assert_eq!(updated.outcome, PassOutcome::Consistent);
        assert!(updated.last_good_ms > saved.last_good_ms, "{updated:?}");
        assert_fresh_v1_durable(&data, &source, updated.last_good_ms)?;
        source_unchanged()?;
    }
    Ok(())
}

fn wire_observation(session: &str, at: i64) -> Value {
    let reported = |value: u64| json!({"value": value, "unit": "tokens", "provenance": "reported", "status": "current"});
    json!({
        "source_id": "src",
        "record_id": quotern_core::domain::tuple_record_id(session, "m"),
        "session_id": session, "message_id": "m", "occurred_at_ms": at,
        "input": reported(1), "output": reported(1), "reasoning": reported(1),
        "cache_read": reported(1), "cache_write": reported(1), "total": reported(5),
        "source_convention": null, "acquisition_consistency": "sqlite_read_transaction",
        "origin_uncertainty": "unverified_origin", "total_mismatch": false,
        "mirror_conflict": false, "selected_part_ids": [], "revision": 1,
        "pending_partial": false, "pending_reason": null
    })
}

#[test]
fn encoded_page_decoder_requires_presence_and_enforces_raw_record_boundaries() -> TestResult {
    use quotern_core::snapshot::ObservationPage;
    let decode = |value: &Value| ObservationPage::decode(&serde_json::to_vec(value).expect("json"));
    let page = |observation: Value| json!({"observations": [observation], "next": null});
    assert!(decode(&page(wire_observation("s", T0))).is_ok(), "control");
    type Mutation = fn(&mut Value);
    let rejected: [(&str, Mutation); 12] = [
        ("omitted next", |p| {
            p.as_object_mut().expect("page").remove("next");
        }),
        ("omitted source_convention", |p| {
            p["observations"][0]
                .as_object_mut()
                .expect("o")
                .remove("source_convention");
        }),
        ("omitted pending_reason", |p| {
            p["observations"][0]
                .as_object_mut()
                .expect("o")
                .remove("pending_reason");
        }),
        ("omitted component provenance", |p| {
            p["observations"][0]["input"]
                .as_object_mut()
                .expect("i")
                .remove("provenance");
        }),
        ("derived component", |p| {
            p["observations"][0]["input"]["provenance"] = json!("derived");
        }),
        ("component above the ceiling", |p| {
            p["observations"][0]["input"]["value"] = json!(1_000_000_000_001_u64);
            p["observations"][0]["total"]["value"] = json!(1_000_000_000_005_u64);
        }),
        ("negative time", |p| {
            p["observations"][0]["occurred_at_ms"] = json!(-1)
        }),
        ("time after the calendar", |p| {
            p["observations"][0]["occurred_at_ms"] = json!(253_402_300_800_000_i64);
        }),
        ("malformed cursor tuple", |p| {
            p["next"] = json!({"occurred_at_ms": T0, "record_id": "not-a-record-tuple"});
        }),
        ("pending without partial status", |p| {
            p["observations"][0]["pending_partial"] = json!(true);
        }),
        ("derived total without convention", |p| {
            p["observations"][0]["total"]["provenance"] = json!("derived");
        }),
        ("duplicate record", |p| {
            let first = p["observations"][0].clone();
            p["observations"].as_array_mut().expect("a").push(first);
        }),
    ];
    for (name, mutate) in rejected {
        let mut value = page(wire_observation("s", T0));
        mutate(&mut value);
        assert!(decode(&value).is_err(), "{name} must be rejected");
    }
    // Siblings that must stay accepted: exactly the ceiling, a cursor equal to the last record.
    let mut at_cap = page(wire_observation("s", T0));
    for field in ["output", "reasoning", "cache_read", "cache_write"] {
        at_cap["observations"][0][field]["value"] = json!(0);
    }
    at_cap["observations"][0]["input"]["value"] = json!(1_000_000_000_000_u64);
    at_cap["observations"][0]["total"]["value"] = json!(1_000_000_000_000_u64);
    assert!(decode(&at_cap).is_ok(), "exactly the ceiling");
    let mut with_next = page(wire_observation("s", T0));
    with_next["next"] = json!({
        "occurred_at_ms": T0,
        "record_id": quotern_core::domain::tuple_record_id("s", "m")
    });
    assert!(
        decode(&with_next).is_ok(),
        "a cursor naming the last record"
    );
    let many: Vec<Value> = (0..1_001)
        .map(|i| wire_observation(&format!("s{i:05}"), T0 + i))
        .collect();
    assert!(
        decode(&json!({"observations": many, "next": null})).is_err(),
        "1,001 records exceed the page limit while decoding"
    );
    Ok(())
}

#[test]
fn encoded_snapshot_decoder_requires_presence_and_projection_relations() -> TestResult {
    use quotern_core::snapshot::SourceSnapshot;
    let unavailable =
        || json!({"value": null, "unit": "tokens", "provenance": null, "status": "unavailable"});
    let snapshot = || {
        json!({
            "source_id": "s", "outcome": "consistent", "failure": null,
            "counters": {"entries": 0, "stat_calls": 0, "header_reads": 0, "directory_opens": 0,
                         "source_opens": 0, "rows_read": 0, "bytes_read": 0, "rejected_records": 0},
            "last_good_ms": null,
            "projection": {
                "records": 0, "input": unavailable(), "output": unavailable(),
                "reasoning": unavailable(), "cache_read": unavailable(),
                "cache_write": unavailable(), "total": unavailable(),
                "source_convention": null, "acquisition_consistency": null,
                "origin_uncertainty": "unverified_origin", "total_mismatch": false,
                "mirror_conflict": false, "pending_partial": false
            }
        })
    };
    let decode = |value: &Value| SourceSnapshot::decode(&serde_json::to_vec(value).expect("json"));
    assert!(decode(&snapshot()).is_ok(), "control: empty projection");
    type Mutation = fn(&mut Value);
    let rejected: [(&str, Mutation); 6] = [
        ("omitted acquisition_consistency", |s| {
            s["projection"]
                .as_object_mut()
                .expect("p")
                .remove("acquisition_consistency");
        }),
        ("omitted source_convention", |s| {
            s["projection"]
                .as_object_mut()
                .expect("p")
                .remove("source_convention");
        }),
        ("omitted failure", |s| {
            s.as_object_mut().expect("s").remove("failure");
        }),
        ("empty projection with a value", |s| {
            s["projection"]["input"] = json!({"value": 3, "unit": "tokens", "provenance": "reported", "status": "current"});
        }),
        ("records without consistency", |s| {
            s["projection"]["records"] = json!(2)
        }),
        ("empty projection with consistency", |s| {
            s["projection"]["acquisition_consistency"] = json!("mixed");
        }),
    ];
    for (name, mutate) in rejected {
        let mut value = snapshot();
        mutate(&mut value);
        assert!(decode(&value).is_err(), "{name} must be rejected");
    }
    Ok(())
}

#[test]
fn durable_range_cursor_algebra_and_spool_presence_fail_with_their_promised_errors() -> TestResult {
    use quotern_core::snapshot::ObservationCursor;
    use quotern_core::store::StoreError;
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    write_json_message(
        &source,
        "s",
        "m",
        T0,
        Some(counts(Some(1), Some(1), Some(1), Some(1), Some(1), None)),
    )?;
    let mut engine = open_engine(&source, &data, &home)?;
    let reports = run_until_consistent(&mut engine, 1, 6);
    let report = reports.last().ok_or("pass")?;
    assert_eq!(report.outcome, PassOutcome::Consistent);
    // Observation cursor: a canonical tuple seeks; every malformed tuple is InvalidStoredValue.
    let cursor = |id: &str| ObservationCursor {
        occurred_at_ms: T0,
        record_id: id.to_owned(),
    };
    assert!(
        engine
            .observations_page(Some(&cursor("opencode:1:s:1:m")), 10)
            .is_ok()
    );
    for bad in [
        "not-a-record-tuple",
        "opencode:9:s:1:m",
        "opencode:1:s:1:mX",
        "opencode:1:s:0:",
        "opencode:x:s:1:m",
    ] {
        assert_eq!(
            engine.observations_page(Some(&cursor(bad)), 10).err(),
            Some(StoreError::InvalidStoredValue),
            "{bad}"
        );
    }
    // Durable record range and time, then the maintained-counter algebra.
    let writer = Connection::open(data.join("history.sqlite"))?;
    writer.execute("UPDATE usage_events SET input_tokens = 1000000000001", [])?;
    assert_eq!(
        engine.observations().err(),
        Some(StoreError::CountOutOfRange)
    );
    writer.execute("UPDATE usage_events SET input_tokens = 1", [])?;
    writer.execute(
        "UPDATE usage_events SET occurred_at_ms = 253402300800000",
        [],
    )?;
    assert_eq!(
        engine.observations().err(),
        Some(StoreError::InvalidStoredValue)
    );
    writer.execute("UPDATE usage_events SET occurred_at_ms = ?1", [T0])?;
    assert_eq!(engine.observations()?.len(), 1, "restored rows read back");
    writer.execute(
        "UPDATE source_projection_totals SET sqlite_count = 0, json_count = 0",
        [],
    )?;
    assert_eq!(
        engine.snapshot(report).err(),
        Some(StoreError::InvalidStoredValue)
    );
    writer.execute(
        "UPDATE source_projection_totals SET json_count = records",
        [],
    )?;
    assert!(
        engine.snapshot(report).is_ok(),
        "a coherent algebra projects"
    );
    Ok(())
}

#[test]
fn staged_candidate_missing_a_required_nullable_key_makes_the_pass_unavailable_with_last_good_kept()
-> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let _c = bulk_legacy(&source.join("opencode.db"), 5_001, 1)?;
    let mut engine = open_engine(&source, &data, &home)?;
    let first = engine.pass(consented(), 1);
    assert_eq!(first.outcome, PassOutcome::CatchingUp);
    let records = engine.snapshot(&first)?.projection.records;
    // Removing the key (not nulling it) must be a decode failure, never an implicit None.
    let writer = Connection::open(data.join("history.sqlite"))?;
    let touched = writer.execute(
        "UPDATE opencode_candidate_spool SET candidate_json = json_remove(candidate_json, '$.source_convention')",
        [],
    )?;
    assert!(touched > 0);
    let mut unavailable = None;
    for step in 0..6 {
        let report = engine.pass(consented(), 2 + step);
        if report.outcome == PassOutcome::Unavailable {
            unavailable = Some(report);
            break;
        }
    }
    let report = unavailable.ok_or("corrupt staged metadata never surfaced")?;
    assert_eq!(
        report.failure,
        Some(FailureCode::InvalidRecord),
        "{report:?}"
    );
    assert_eq!(report.last_good_ms, Some(1), "last-good is retained");
    assert_eq!(
        engine.snapshot(&report)?.projection.records,
        records,
        "history retained"
    );
    Ok(())
}

#[test]
fn a_part_group_changed_between_passes_is_never_published_under_a_stale_label() -> TestResult {
    let _guard = vfs_test_guard();
    for reopen in [false, true] {
        let directory = tempdir()?;
        let (source, data, home) = source_roots(directory.path())?;
        let path = source.join("opencode.db");
        let c = open_fixture(&path)?;
        let tx = c.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO message(id, session_id, time_created, data) VALUES ('m0', 's', ?1, ?2)",
            rusqlite::params![T0, br#"{"role":"assistant"}"#.to_vec()],
        )?;
        let insert_part = |id: String, data: Vec<u8>| {
            tx.execute(
                "INSERT INTO part(id, message_id, session_id, time_created, data) VALUES (?1, 'm0', 's', 1, ?2)",
                rusqlite::params![id, data],
            )
        };
        let filler = br#"{"type":"text","text":"x"}"#.to_vec();
        for index in 0..3_000 {
            insert_part(format!("a-{index:05}"), filler.clone())?;
        }
        let finish = |input: u64| {
            serde_json::to_vec(&step_finish(counts(
                Some(input),
                None,
                None,
                None,
                None,
                None,
            )))
        };
        insert_part("z-1".to_owned(), finish(40)?)?;
        insert_part("z-2".to_owned(), finish(60)?)?;
        tx.commit()?;
        drop(c);
        let mut engine = open_engine(&source, &data, &home)?;
        let first = engine.pass(consented(), 1);
        assert_eq!(first.outcome, PassOutcome::CatchingUp, "{first:?}");
        assert_eq!(engine.snapshot(&first)?.projection.records, 0);
        // A step-finish part appears behind the suspension point between the two passes.
        let writer = Connection::open(&path)?;
        writer.execute(
            "INSERT INTO part(id, message_id, session_id, time_created, data) VALUES ('a-00000x', 'm0', 's', 1, ?1)",
            [finish(5)?],
        )?;
        drop(writer);
        if reopen {
            drop(engine);
            engine = open_engine(&source, &data, &home)?;
        }
        let mut last = None;
        for step in 0..12 {
            let report = engine.pass(consented(), 2 + step);
            let projection = engine.snapshot(&report)?.projection;
            assert!(
                matches!(projection.input.value, None | Some(105)),
                "reopen={reopen}: published {:?} (stale 100 would mean a mixed group)",
                projection.input.value
            );
            let done = report.outcome == PassOutcome::Consistent;
            last = Some(report);
            if done {
                break;
            }
        }
        let last = last.ok_or("pass")?;
        assert_eq!(
            last.outcome,
            PassOutcome::Consistent,
            "reopen={reopen}: {last:?}"
        );
        assert_eq!(
            engine.snapshot(&last)?.projection.input.value,
            Some(105),
            "reopen={reopen}"
        );
    }
    Ok(())
}

#[test]
fn more_than_1024_completed_databases_drain_to_an_exact_terminal_publication() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    for index in 0..1_100 {
        let c = bulk_legacy(&source.join(format!("opencode-{index:04}.db")), 1, 1)?;
        let (id, session) = (format!("m{index}"), format!("s{index}"));
        c.execute(
            "UPDATE message SET id = ?1, session_id = ?2",
            rusqlite::params![id, session],
        )?;
        c.execute(
            "UPDATE part SET message_id = ?1, session_id = ?2",
            rusqlite::params![id, session],
        )?;
    }
    let mut engine = open_engine(&source, &data, &home)?;
    let mut peak_completed = 0_i64;
    let mut last = None;
    for step in 0..80 {
        let report = engine.pass(consented(), 1 + step);
        let completed: i64 = scalar(
            &data,
            "SELECT COUNT(*) FROM metadata_spool WHERE parser_kind = 'sqlite'",
        )?;
        peak_completed = peak_completed.max(completed);
        let done = report.outcome == PassOutcome::Consistent;
        last = Some(report);
        if done {
            break;
        }
    }
    let last = last.ok_or("pass")?;
    assert_eq!(last.outcome, PassOutcome::Consistent, "{last:?}");
    assert!(
        peak_completed > 1_024,
        "the generation really held {peak_completed} databases"
    );
    let projection = engine.snapshot(&last)?.projection;
    assert_eq!(
        (projection.records, projection.input.value),
        (1_100, Some(1_100))
    );
    Ok(())
}

#[test]
fn json_group_of_more_than_40000_raw_parts_drains_across_one_reopen_to_exact_numbers() -> TestResult
{
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(&directory.path().canonicalize()?)?;
    write_json_message(&source, "s", "m", T0, None)?;
    let filler = json!({"type": "text"});
    for index in 0..40_010 {
        write_json_part(&source, "m", &format!("p{index:05}"), &filler)?;
    }
    write_json_part(
        &source,
        "m",
        "z-finish",
        &step_finish(counts(Some(7), None, None, None, None, None)),
    )?;
    let mut engine = open_engine(&source, &data, &home)?;
    let mut finished = None;
    for pass in 0..160_i64 {
        if pass == 3 {
            // The held scan is only in memory: the group is neither staged as a source file nor
            // published, while the directory that lists its message is still durably pending.
            let staged_files: i64 = scalar(
                &data,
                "SELECT COUNT(*) FROM metadata_spool WHERE parser_kind <> 'directory'",
            )?;
            let published_files: i64 = scalar(&data, "SELECT COUNT(*) FROM source_files")?;
            let pending_listing: i64 = scalar(
                &data,
                "SELECT COUNT(*) FROM frontier_directories WHERE relative_path = 'storage/message/s'",
            )?;
            assert_eq!(
                (staged_files, published_files, pending_listing),
                (0, 0, 1),
                "pass {pass}: staged versus published state before the restart"
            );
            // One restart in the middle: unfinished iterator state is reconstructed from the
            // beginning, completed durable state is kept.
            drop(engine);
            engine = open_engine(&source, &data, &home)?;
        }
        let report = engine.pass(consented(), 1 + pass);
        assert!(
            report.counters.stat_calls <= 40_000,
            "pass {pass}: {report:?}"
        );
        assert!(report.counters.entries <= 20_000, "pass {pass}: {report:?}");
        assert!(
            report.counters.bytes_read <= 64 * 1024 * 1024,
            "pass {pass}: {report:?}"
        );
        assert_ne!(
            report.failure,
            Some(FailureCode::SourceIdle),
            "pass {pass}: a live source with a held scan is never idle: {report:?}"
        );
        let queued: i64 = scalar(&data, "SELECT COUNT(*) FROM frontier_directories")?;
        assert!(
            usize::try_from(queued)? <= quotern_core::limits::MAX_FRONTIER_DIRECTORIES,
            "pass {pass}: {queued} persisted frontier directories"
        );
        let projection = engine.snapshot(&report)?.projection;
        if report.outcome == PassOutcome::Consistent {
            assert!(report.last_good_ms.is_some(), "pass {pass}: {report:?}");
            finished = Some(projection);
            break;
        }
        assert_eq!(
            report.outcome,
            PassOutcome::CatchingUp,
            "pass {pass}: an unfinished group is catching up: {report:?}"
        );
        assert_eq!(
            report.last_good_ms, None,
            "pass {pass}: staging alone never advances last-good: {report:?}"
        );
        assert_eq!(
            projection.records, 0,
            "pass {pass}: nothing is published before the whole group is read: {report:?}"
        );
    }
    let projection = finished.ok_or("the finite group never drained")?;
    assert_eq!((projection.records, projection.input.value), (1, Some(7)));
    let published_messages: i64 = scalar(
        &data,
        "SELECT COUNT(*) FROM source_files WHERE adapter_state = 'opencode_json_message' \
         AND file_state = 'present'",
    )?;
    assert_eq!(published_messages, 1);
    Ok(())
}

#[test]
fn unfinished_json_parts_reopen_without_advancing_last_good() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(&directory.path().canonicalize()?)?;
    write_json_message(&source, "s", "g", T0, None)?;
    for (id, input) in [("p1", 40), ("p2", 60)] {
        let tokens = counts(Some(input), None, None, None, None, None);
        write_json_part(&source, "g", id, &step_finish(tokens))?;
    }
    let mut engine = open_engine(&source, &data, &home)?;
    let baseline = engine.pass(consented(), 1);
    assert_eq!(baseline.outcome, PassOutcome::Consistent, "{baseline:?}");
    let baseline_good = baseline.last_good_ms;
    assert!(baseline_good.is_some(), "{baseline:?}");
    let published = group_state(&engine, "g")?;
    assert_eq!(
        (published.0, published.1, published.2),
        (Some(100), 1, false)
    );

    // The known message now has more harmless part entries than the reserved lane reads in one
    // pass, and one of its parts changes to an explicit zero.
    for index in 0..20_001 {
        let note = source.join(format!("storage/part/g/note{index:05}.txt"));
        std::fs::write(note, b"")?;
    }
    let zero = counts(Some(0), None, None, None, None, None);
    write_json_part(&source, "g", "p2", &step_finish(zero))?;

    let mut reopened = false;
    let mut incomplete_after_reopen = 0;
    let mut finished = None;
    for step in 0..60_i64 {
        let report = engine.pass(consented(), 2 + step);
        assert!(report.counters.entries <= 20_000, "step {step}: {report:?}");
        if report.outcome == PassOutcome::Consistent {
            finished = Some(report);
            break;
        }
        // Pure staging: the retained group, its revision and the last-good time do not move.
        assert_eq!(
            report.outcome,
            PassOutcome::CatchingUp,
            "step {step}: {report:?}"
        );
        assert_eq!(report.records_committed, 0, "step {step}: {report:?}");
        assert_eq!(report.last_good_ms, baseline_good, "step {step}");
        assert_eq!(
            scalar::<Option<i64>>(&data, "SELECT last_success_ms FROM source_status")?,
            baseline_good,
            "step {step}: durable last-good"
        );
        assert_eq!(group_state(&engine, "g")?, published, "step {step}");
        let projection = engine.snapshot(&report)?.projection;
        assert_eq!(
            (projection.records, projection.input.value),
            (1, Some(100)),
            "step {step}"
        );
        assert_eq!(scalar::<i64>(&data, "SELECT dirty FROM sources")?, 1);
        if reopened {
            incomplete_after_reopen += 1;
        } else {
            // One restart in the middle of the unfinished scan.
            drop(engine);
            engine = open_engine(&source, &data, &home)?;
            reopened = true;
        }
    }
    let finished = finished.ok_or("the finite group never drained")?;
    assert!(reopened, "the first pass already finished the scan");
    assert!(
        incomplete_after_reopen > 0,
        "the restarted scan finished in its first pass"
    );
    assert!(finished.last_good_ms > baseline_good, "{finished:?}");
    let settled = group_state(&engine, "g")?;
    assert_eq!(
        (settled.0, settled.1, settled.2),
        (Some(40), 2, false),
        "the corrected group replaces the retained one exactly once"
    );
    assert_eq!(settled.4, published.4);
    assert_eq!(scalar::<i64>(&data, "SELECT dirty FROM sources")?, 0);
    let again = run_until_consistent(&mut engine, 1_000_000, 3);
    assert_eq!(again.last().ok_or("pass")?.outcome, PassOutcome::Consistent);
    assert_eq!(group_state(&engine, "g")?, settled, "stable reacquisition");
    Ok(())
}

/// Every file and directory under `root` with its size and modification time.
fn source_tree_stamps(root: &Path) -> TestResult<Vec<(PathBuf, u64, std::time::SystemTime)>> {
    let mut stamps = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            stamps.push((entry.path(), metadata.len(), metadata.modified()?));
            if metadata.is_dir() {
                stack.push(entry.path());
            }
        }
    }
    stamps.sort();
    Ok(stamps)
}

/// Recording filesystem that also records every directory whose listing was read to its end.
#[derive(Clone)]
struct EofFs {
    inner: RecordingFs,
    eofs: Arc<std::sync::Mutex<std::collections::BTreeSet<PathBuf>>>,
}

struct EofEntries {
    entries: quotern_core::ingest::fs::DirEntries,
    path: PathBuf,
    eofs: Arc<std::sync::Mutex<std::collections::BTreeSet<PathBuf>>>,
}

impl Iterator for EofEntries {
    type Item = std::io::Result<PathBuf>;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.entries.next();
        if entry.is_none()
            && let Ok(mut eofs) = self.eofs.lock()
        {
            eofs.insert(self.path.clone());
        }
        entry
    }
}

impl EofFs {
    fn new() -> Self {
        Self {
            inner: RecordingFs::new(),
            eofs: Arc::default(),
        }
    }

    fn eof_set(&self) -> std::collections::BTreeSet<PathBuf> {
        self.eofs.lock().expect("eof set").clone()
    }

    /// Starts a new observation epoch: only listings read to their end from now on count. The
    /// set is shared by every engine opened from this filesystem, so one epoch spans a reopen.
    fn start_epoch(&self) {
        self.eofs.lock().expect("eof set").clear();
    }
}

/// Runs one source filesystem call as source work for the native physical observer, ancestor
/// probes included (macOS arm64). Elsewhere it only calls `call`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn source_window<T>(call: impl FnOnce() -> T) -> T {
    let _focus = support::physical_native::Focus::enter();
    call()
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn source_window<T>(call: impl FnOnce() -> T) -> T {
    call()
}

impl quotern_core::ingest::fs::SourceFs for EofFs {
    fn canonicalize(
        &self,
        path: &Path,
        counters: &mut quotern_core::domain::PassCounters,
    ) -> std::io::Result<PathBuf> {
        source_window(|| self.inner.canonicalize(path, counters))
    }

    fn metadata(
        &self,
        path: &Path,
        counters: &mut quotern_core::domain::PassCounters,
    ) -> std::io::Result<std::fs::Metadata> {
        source_window(|| self.inner.metadata(path, counters))
    }

    fn read_dir(
        &self,
        path: &Path,
        counters: &mut quotern_core::domain::PassCounters,
    ) -> std::io::Result<quotern_core::ingest::fs::DirEntries> {
        let entries = source_window(|| self.inner.read_dir(path, counters))?;
        Ok(Box::new(EofEntries {
            entries,
            path: path.to_path_buf(),
            eofs: Arc::clone(&self.eofs),
        }))
    }

    fn read_header(
        &self,
        path: &Path,
        counters: &mut quotern_core::domain::PassCounters,
    ) -> std::io::Result<Vec<u8>> {
        source_window(|| self.inner.read_header(path, counters))
    }

    fn read_bounded(
        &self,
        path: &Path,
        max_bytes: usize,
        counters: &mut quotern_core::domain::PassCounters,
    ) -> std::io::Result<quotern_core::ingest::fs::BoundedRead> {
        source_window(|| self.inner.read_bounded(path, max_bytes, counters))
    }

    fn open_sqlite(
        &self,
        path: &Path,
    ) -> Result<Connection, quotern_core::ingest::sqlite_ro::OpenError> {
        source_window(|| self.inner.open_sqlite(path))
    }
}

fn open_eof_engine(
    fs: &EofFs,
    source: &Path,
    data: &Path,
    home: &Path,
) -> TestResult<OpenCodeEngine<EofFs>> {
    OpenCodeEngine::open(
        fs.clone(),
        source,
        data,
        home,
        consented(),
        quotern_core::domain::SourceKind::Custom,
    )
    .map_err(|report| format!("OpenCode engine failed: {report:?}").into())
}

/// `root` and every directory below it, read independently of the engine.
fn directory_set(root: &Path) -> TestResult<std::collections::BTreeSet<PathBuf>> {
    let mut directories = std::collections::BTreeSet::from([root.to_path_buf()]);
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            if entry.metadata()?.is_dir() {
                directories.insert(entry.path());
                stack.push(entry.path());
            }
        }
    }
    Ok(directories)
}

// ---------------------------------------------------------------------------------------------
// Independent native physical accounting of whole-engine passes (macOS arm64 only).
//
// `support::physical_native` exports the C symbols the production code, Rust `std` and the bundled
// SQLite call, and counts the attempts that cross that native API with a source path or source
// descriptor, beneath every production counter, tick and hook. `Meter` reads none of those; it
// compares the native counts of EVERY pass with the literal ceilings (40,000 metadata calls, 64
// directory opens, 8 held streams, 20,000 yielded entries, 64 MiB of JSON bytes, no writable
// source descriptor, no coverage fault) and with what the pass reported. The observer replaces
// process-wide symbols, so a test that arms it runs as the only test of one re-executed copy of
// this binary and arms it after its fixtures exist.
// ---------------------------------------------------------------------------------------------

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod native {
    use std::cell::Cell;
    use std::ffi::c_int;
    use std::process::Command;

    use super::*;
    use crate::support::physical_native::{Observer, json_within, within};

    const CHILD_ENV: &str = "QUOTERN_WAL_PHYSICAL_NATIVE_CHILD";

    /// A child that has not finished by then is killed and the test fails.
    const CHILD_TIMEOUT: Duration = Duration::from_secs(900);

    unsafe extern "C" {
        fn kill(pid: c_int, signal: c_int) -> c_int;
    }

    /// Runs `name` as the only test of a re-executed copy of this binary (`--test-threads=1`),
    /// bounded by [`CHILD_TIMEOUT`]; inside that copy it runs `body`.
    pub fn isolated(name: &str, body: fn() -> TestResult) -> TestResult {
        if std::env::var_os(CHILD_ENV).is_some_and(|value| value == name) {
            return body();
        }
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

    /// The armed observer of one test, with the largest native counts of its passes.
    pub struct Meter {
        observer: Observer,
        passes: Cell<u64>,
        peaks: Cell<[u64; 4]>,
    }

    impl Meter {
        /// Arms the observer on the canonical `source` root. Call it after every fixture exists.
        pub fn arm(source: &Path) -> Self {
            Self {
                observer: Observer::start(source),
                passes: Cell::new(0),
                peaks: Cell::new([0; 4]),
            }
        }

        pub fn begin(&self) {
            self.observer.begin_pass();
        }

        /// The native counts of the pass that just ran. `requested` is the byte count the
        /// production reads asked for; JSON acquisition materializes exactly the bytes it read.
        pub fn check(&self, counters: &PassCounters, requested: u64, label: &str) {
            let native = self.observer.snapshot();
            assert!(
                within(native) && json_within(native),
                "{label}: native work outside the literal ceilings: {native:?}"
            );
            assert!(
                native.peak <= 8 && native.held <= native.peak,
                "{label}: held directory streams: {native:?}"
            );
            assert_eq!(native.writable, 0, "{label}: {native:?}");
            assert_eq!(native.coverage_faults, 0, "{label}: {native:?}");
            for (what, charged, seen) in [
                ("metadata", u64::from(counters.stat_calls), native.metadata),
                ("opens", u64::from(counters.directory_opens), native.opens),
                ("yields", u64::from(counters.entries), native.yields),
                ("bytes", counters.bytes_read, native.bytes),
            ] {
                assert_eq!(
                    charged, seen,
                    "{label}: {what} charged {charged}, native {seen}: {native:?}"
                );
            }
            assert!(
                native.bytes <= requested,
                "{label}: {} bytes read but only {requested} requested",
                native.bytes
            );
            self.passes.set(self.passes.get() + 1);
            let seen = [native.metadata, native.opens, native.yields, native.peak];
            let mut peaks = self.peaks.get();
            for (peak, now) in peaks.iter_mut().zip(seen) {
                *peak = (*peak).max(now);
            }
            self.peaks.set(peaks);
        }

        /// No directory stream, tracked descriptor or coverage fault remains. Every engine that
        /// read the source has been dropped before this is called.
        pub fn assert_clean(&self, label: &str) {
            assert!(
                self.observer.clean(),
                "{label}: the observer still holds a stream or descriptor, or saw a fault: {:?}",
                self.observer.snapshot()
            );
        }

        pub fn finish(self, name: &str) {
            let [metadata, opens, yields, peak] = self.peaks.get();
            println!(
                "PHYSICAL {name}: {} passes, at most {metadata} metadata, {opens} opens, \
                 {yields} yields, {peak} held streams",
                self.passes.get()
            );
        }
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
mod native {
    use super::*;

    pub fn isolated(_name: &str, body: fn() -> TestResult) -> TestResult {
        body()
    }

    /// No native physical observer exists on this platform.
    pub struct Meter;

    impl Meter {
        pub fn arm(_source: &Path) -> Self {
            Self
        }

        pub fn begin(&self) {}

        pub fn check(&self, _: &PassCounters, _: u64, _: &str) {}

        pub fn assert_clean(&self, _: &str) {}

        pub fn finish(self, _: &str) {}
    }
}

use quotern_core::domain::PassCounters;

/// One pass whose work is measured physically and compared with the independently pinned
/// per-pass ceilings (literals, not the production constants) and with what the pass reported.
/// `meter` adds the native observation of the same pass, which reads none of the production
/// counters.
fn bounded_pass<F: quotern_core::ingest::fs::SourceFs>(
    engine: &mut OpenCodeEngine<F>,
    recording: &RecordingFs,
    meter: &native::Meter,
    now_ms: i64,
    label: &str,
) -> PassReport {
    use quotern_core::ingest::fs::physical_operations;
    let (physical, metrics) = (physical_operations(), recording.metrics());
    meter.begin();
    let report = engine.pass(consented(), now_ms);
    let after = physical_operations();
    let (metadata, opens, yields, requested) = (
        after.metadata - physical.metadata,
        after.directory_opens - physical.directory_opens,
        after.directory_yields - physical.directory_yields,
        after.bytes_requested - physical.bytes_requested,
    );
    let counters = report.counters;
    assert!(counters.entries <= 20_000, "{label}: {report:?}");
    assert!(counters.stat_calls <= 40_000, "{label}: {report:?}");
    assert!(counters.directory_opens <= 64, "{label}: {report:?}");
    assert!(counters.rows_read <= 5_000, "{label}: {report:?}");
    assert!(
        counters.bytes_read <= 64 * 1024 * 1024,
        "{label}: {report:?}"
    );
    assert!(
        metadata <= 40_000 && opens <= 64 && yields <= 20_000,
        "{label}: physical {metadata}/{opens}/{yields}"
    );
    assert!(
        requested <= 64 * 1024 * 1024,
        "{label}: physically requested {requested} bytes"
    );
    // The same pass as the native API boundary saw it, whatever the production code charged.
    meter.check(&counters, requested, label);
    assert!(
        recording.metrics().max_open_directories <= 8,
        "{label}: {:?}",
        recording.metrics()
    );
    // Reported work equals the work physically performed: replay is charged, never free.
    assert_eq!(
        u64::from(counters.stat_calls),
        metadata,
        "{label}: {report:?}"
    );
    assert_eq!(
        u64::from(counters.directory_opens),
        opens,
        "{label}: {report:?}"
    );
    assert_eq!(u64::from(counters.entries), yields, "{label}: {report:?}");
    assert_eq!(
        recording.metrics().directory_opens - metrics.directory_opens,
        opens,
        "{label}"
    );
    report
}

/// A message directory of 4,500 session directories and six directories of 700 children each keep
/// every iterator slot busy while the queue fills to its 4,096-directory ceiling. Without and with
/// one restart after the ceiling was reached, every directory of the tree is read to its end and
/// every session is published before any pass is consistent, no pass exceeds the pinned work
/// ceilings, and the persisted queue never exceeds 4,096.
#[test]
fn directories_beyond_the_queue_ceiling_are_fully_inventoried() -> TestResult {
    native::isolated(
        "directories_beyond_the_queue_ceiling_are_fully_inventoried",
        queue_ceiling_inventory,
    )
}

fn queue_ceiling_inventory() -> TestResult {
    const SESSIONS: u64 = 4_500;
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, _, home) = source_roots(&directory.path().canonicalize()?)?;
    let tokens = counts(Some(1), None, None, None, None, Some(1));
    for index in 0..SESSIONS {
        let (session, message) = (format!("s{index:04}"), format!("m{index:04}"));
        write_json_message(&source, &session, &message, T0, Some(tokens.clone()))?;
    }
    for parent in 0..6 {
        for child in 0..700 {
            std::fs::create_dir_all(source.join(format!("wide-{parent}/dir-{child:03}")))?;
        }
    }
    let before = source_tree_stamps(&source)?;
    let expected_directories = directory_set(&source)?;
    assert_eq!(
        expected_directories.len() as u64,
        1 + 1 + 1 + SESSIONS + 6 + 4_200
    );
    let meter = native::Meter::arm(&source);
    for reopen in [false, true] {
        let data = directory.path().join(format!("data-{reopen}"));
        let fs = EofFs::new();
        let mut engine = open_eof_engine(&fs, &source, &data, &home)?;
        let mut saturated_at = None;
        let mut finished = None;
        for pass in 0..800_i64 {
            if reopen && saturated_at.is_some_and(|at| pass == at + 2) {
                drop(engine);
                engine = open_eof_engine(&fs, &source, &data, &home)?;
            }
            let label = format!("reopen={reopen} pass {pass}");
            let report = bounded_pass(&mut engine, &fs.inner, &meter, 1 + pass, &label);
            let queued: i64 = scalar(&data, "SELECT COUNT(*) FROM frontier_directories")?;
            assert!(
                queued <= 4_096,
                "{label}: {queued} persisted frontier directories"
            );
            if report.failure == Some(FailureCode::LimitExceeded) && queued == 4_096 {
                saturated_at.get_or_insert(pass);
            }
            let projection = engine.snapshot(&report)?.projection;
            if report.outcome == PassOutcome::Consistent {
                // No Consistent report before every directory of the fixture reached its end.
                assert_eq!(
                    fs.eof_set(),
                    expected_directories,
                    "{label}: directories that never reached EOF"
                );
                finished = Some((report, projection));
                break;
            }
            assert!(projection.records <= SESSIONS, "{label}: {report:?}");
        }
        let (report, projection) = finished.ok_or("the finite tree never drained")?;
        assert!(
            saturated_at.is_some(),
            "the queue never reached its ceiling"
        );
        assert_eq!(report.failure, None, "reopen={reopen}: {report:?}");
        assert_eq!(
            (projection.records, projection.input.value),
            (SESSIONS, Some(SESSIONS)),
            "reopen={reopen}: a consistent pass must have listed every child directory"
        );
        let published: i64 = scalar(
            &data,
            "SELECT COUNT(*) FROM source_files WHERE adapter_state = 'opencode_json_message' \
             AND file_state = 'present'",
        )?;
        assert_eq!(published, SESSIONS as i64, "reopen={reopen}");
        // The last engine of the scenario is gone: no stream or descriptor of the source is
        // still held, and no coverage fault was ever recorded.
        drop(engine);
        meter.assert_clean(&format!("reopen={reopen}"));
        assert_eq!(source_tree_stamps(&source)?, before, "source untouched");
    }
    meter.finish("directories_beyond_the_queue_ceiling_are_fully_inventoried");
    Ok(())
}

/// 300 stable, fully published JSON messages without part directories cost slightly more to
/// refresh than the reserved current lane's half of the metadata budget, so the lane ends every
/// pass with a held final revalidation. After one restart the generation still ends, once the
/// directory frontier and every held scan have drained. Every refresh, reconstruction and
/// terminal pass keeps the 300 published records and their totals, stays dirty and keeps the
/// last-good time until the clean completion, stays inside the pinned work ceilings, and the
/// source is never touched.
#[test]
fn stable_known_messages_beyond_the_current_lane_budget_reach_consistent_across_one_reopen()
-> TestResult {
    native::isolated(
        "stable_known_messages_beyond_the_current_lane_budget_reach_consistent_across_one_reopen",
        current_lane_refresh,
    )
}

fn current_lane_refresh() -> TestResult {
    const MESSAGES: u64 = 300;
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(&directory.path().canonicalize()?)?;
    let tokens = counts(Some(1), None, None, None, None, Some(1));
    for index in 0..MESSAGES {
        let message = format!("m{index:03}");
        write_json_message(&source, "s", &message, T0, Some(tokens.clone()))?;
    }
    let before = source_tree_stamps(&source)?;
    let expected_directories = directory_set(&source)?;
    let meter = native::Meter::arm(&source);
    let fs = EofFs::new();
    let mut engine = open_eof_engine(&fs, &source, &data, &home)?;
    let mut baseline = None;
    let mut baseline_time = 0;
    for pass in 0..400_i64 {
        baseline_time = 1 + pass;
        let report = bounded_pass(
            &mut engine,
            &fs.inner,
            &meter,
            baseline_time,
            &format!("baseline {pass}"),
        );
        let done = report.outcome == PassOutcome::Consistent;
        baseline = Some(report);
        if done {
            break;
        }
    }
    let baseline = baseline.ok_or("no baseline pass")?;
    assert_eq!(baseline.outcome, PassOutcome::Consistent, "{baseline:?}");
    assert_eq!(fs.eof_set(), expected_directories);
    // The terminal pass publishes at exactly its own injected time.
    let baseline_good = baseline.last_good_ms;
    assert_eq!(baseline_good, Some(baseline_time), "{baseline:?}");
    let published = engine.snapshot(&baseline)?.projection;
    assert_eq!(
        (
            published.records,
            published.input.value,
            published.total.value
        ),
        (MESSAGES, Some(MESSAGES), Some(MESSAGES))
    );
    let identities = |data: &Path| -> TestResult<Vec<(String, i64)>> {
        Ok(history(data)?
            .prepare("SELECT event_key, revision FROM usage_events ORDER BY event_key")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?)
    };
    let retained = identities(&data)?;
    assert_eq!(retained.len() as u64, MESSAGES);
    assert!(retained.iter().all(|(_, revision)| *revision == 1));
    assert_eq!(scalar::<i64>(&data, "SELECT dirty FROM sources")?, 0);
    assert_eq!(
        scalar::<Option<i64>>(&data, "SELECT last_success_ms FROM source_status")?,
        baseline_good
    );

    // The next generation refreshes the known messages; restart once in the middle of it. It is
    // a new generation, so it needs its own EOF evidence: the observation epoch starts empty here
    // and is kept across the one reopen, and only listings read to their end within it count.
    fs.start_epoch();
    assert!(fs.eof_set().is_empty(), "a fresh refresh epoch");
    assert_eq!(directory_set(&source)?, expected_directories);
    let mut previous_good = baseline_good;
    let mut catching_up = 0;
    let mut restart_blocked = 0_i64;
    let mut finished = None;
    for pass in 0..400_i64 {
        if pass == 3 {
            restart_blocked = scalar::<i64>(
                &data,
                "SELECT COUNT(*) FROM frontier_directories WHERE restart_blocked = 1",
            )?;
            drop(engine);
            engine = open_eof_engine(&fs, &source, &data, &home)?;
        }
        let label = format!("refresh {pass}");
        let report = bounded_pass(&mut engine, &fs.inner, &meter, 1_000 + pass, &label);
        let projection = engine.snapshot(&report)?.projection;
        // Every pass, terminal one included, still exposes the retained history exactly.
        assert_eq!(
            (
                projection.records,
                projection.input.value,
                projection.total.value
            ),
            (MESSAGES, Some(MESSAGES), Some(MESSAGES)),
            "{label}: {report:?}"
        );
        assert_eq!(
            identities(&data)?,
            retained,
            "{label}: identities and revisions"
        );
        assert_eq!(
            scalar::<Option<i64>>(&data, "SELECT last_success_ms FROM source_status")?,
            report.last_good_ms,
            "{label}: report and durable last-good agree"
        );
        if report.outcome == PassOutcome::Consistent {
            // Only a refresh epoch that read every directory of the tree to its end certifies,
            // and the terminal pass advances last-good to exactly its own injected time, in the
            // report and in the durable status.
            assert_eq!(fs.eof_set(), expected_directories, "{label}: refresh epoch");
            assert_eq!(
                report.last_good_ms,
                Some(1_000 + pass),
                "{label}: {report:?}"
            );
            assert_eq!(
                scalar::<Option<i64>>(&data, "SELECT last_success_ms FROM source_status")?,
                Some(1_000 + pass),
                "{label}: durable terminal time"
            );
            finished = Some(report);
            break;
        }
        // The designated reconstruction pass is the first one after the restart, selected by the
        // restart-blocked directories read from the durable frontier before the engine was
        // dropped, never by the report under test: the listing that was in progress is read
        // again from its beginning, and that pass must say so.
        let reconstruction = pass == 3 && restart_blocked > 0;
        if reconstruction {
            assert_eq!(
                (report.outcome, report.failure),
                (PassOutcome::Partial, Some(FailureCode::LimitExceeded)),
                "{label}: {report:?}"
            );
            // Reconstruction stages nothing for publication: no record is committed and the
            // last-good time stays the previous one, whatever else the report says.
            assert_eq!(report.records_committed, 0, "{label}: {report:?}");
            assert_eq!(report.last_good_ms, previous_good, "{label}: {report:?}");
            assert_eq!(
                scalar::<Option<i64>>(&data, "SELECT last_success_ms FROM source_status")?,
                previous_good,
                "{label}: durable last-good unchanged"
            );
        } else {
            assert_eq!(
                report.outcome,
                PassOutcome::CatchingUp,
                "{label}: {report:?}"
            );
            assert_eq!(report.failure, None, "{label}: {report:?}");
        }
        // Staging-only work (nothing published) never advances last-good; a pass that published
        // completed records advances it exactly to its own time. The reconciliation stays dirty.
        if report.records_committed == 0 {
            assert_eq!(report.last_good_ms, previous_good, "{label}: {report:?}");
        } else {
            assert_eq!(
                report.last_good_ms,
                Some(1_000 + pass),
                "{label}: {report:?}"
            );
        }
        previous_good = report.last_good_ms;
        assert_eq!(
            scalar::<i64>(&data, "SELECT dirty FROM sources")?,
            1,
            "{label}"
        );
        catching_up += 1;
    }
    let report = finished.ok_or("the finite stable tree never reached consistent")?;
    assert!(catching_up > 3, "the refresh fit one pass: {catching_up}");
    assert!(
        restart_blocked > 0,
        "no restart-blocked directory was persisted before the reopen: nothing designated a reconstruction pass"
    );
    assert_eq!(report.failure, None, "{report:?}");
    assert!(report.last_good_ms > baseline_good, "{report:?}");
    let projection = engine.snapshot(&report)?.projection;
    assert_eq!(
        (projection.records, projection.input.value),
        (MESSAGES, Some(MESSAGES))
    );
    assert_eq!(scalar::<i64>(&data, "SELECT dirty FROM sources")?, 0);
    for message in ["m000", "m299"] {
        let state = group_state(&engine, message)?;
        assert_eq!(
            (state.0, state.1, state.2),
            (Some(1), 1, false),
            "{message}"
        );
    }
    // Every engine is gone: no stream or descriptor of the source is held, no fault recorded.
    drop(engine);
    meter.assert_clean("current-lane refresh");
    meter.finish(
        "stable_known_messages_beyond_the_current_lane_budget_reach_consistent_across_one_reopen",
    );
    assert_eq!(source_tree_stamps(&source)?, before, "source untouched");
    Ok(())
}

/// 1,089 independent rollback databases of one message each: five explicit components of
/// `[1, 0, 0, 0, 0]` and an explicit total of 1. More than the 64 databases one pass may open
/// cross 1,024 completed databases before the generation can end.
fn single_message_databases(source: &Path) -> TestResult {
    for index in 0..1_089_i64 {
        let connection = open_fixture(&source.join(format!("opencode-{index:04}.db")))?;
        put_message(
            &connection,
            &format!("m-{index:04}"),
            "s",
            T0 + index,
            &assistant(counts(Some(1), Some(0), Some(0), Some(0), Some(0), Some(1))),
        )?;
    }
    Ok(())
}

/// Every durable observation, paged through the encoded decoder.
fn all_observations<F: quotern_core::ingest::fs::SourceFs>(
    engine: &OpenCodeEngine<F>,
) -> TestResult<Vec<SourceReportedObservation>> {
    use quotern_core::snapshot::ObservationPage;
    let (mut observations, mut cursor) = (Vec::new(), None);
    loop {
        let page = ObservationPage::decode(&serde_json::to_vec(
            &engine.observations_page(cursor.as_ref(), 1_000)?,
        )?)?;
        observations.extend(page.observations);
        match page.next {
            Some(next) => cursor = Some(next),
            None => return Ok(observations),
        }
    }
}

/// What a consistent report over the 1,089 databases must expose: every record once with one
/// token, except the edited one, in the decoded snapshot and in every decoded history page.
fn assert_database_consumers<F: quotern_core::ingest::fs::SourceFs>(
    engine: &OpenCodeEngine<F>,
    report: &PassReport,
    data: &Path,
    edited: Option<(&str, u64)>,
) -> TestResult {
    use quotern_core::snapshot::SourceSnapshot;
    let total = 1_089 + edited.map_or(0, |(_, value)| value - 1);
    let snapshot = SourceSnapshot::decode(&serde_json::to_vec(&engine.snapshot(report)?)?)?;
    let durable_source: String = scalar(data, "SELECT source_id FROM sources")?;
    assert_eq!(
        snapshot.source_id, durable_source,
        "durable source identity"
    );
    assert_eq!(snapshot.projection.records, 1_089);
    assert_eq!(
        snapshot.projection.input.value,
        Some(total),
        "certification must include the edited completed database"
    );
    assert_eq!(snapshot.projection.total.value, Some(total));
    let observations = all_observations(engine)?;
    let ids: std::collections::BTreeSet<&str> = observations
        .iter()
        .map(|record| record.message_id.as_str())
        .collect();
    assert_eq!(observations.len(), 1_089);
    assert_eq!(ids.len(), 1_089, "unique message identities");
    // The complete expected identity and time set, written from the fixture index alone: source,
    // session, message, canonical record id, occurrence time, input value and revision of each of
    // the 1,089 records, in the decoded pages, in their page order and in the durable events.
    type Tuple = (String, String, String, String, i64, u64, u64);
    let expected: Vec<Tuple> = (0..1_089_i64)
        .map(|index| {
            let message = format!("m-{index:04}");
            let (value, revision) = match edited {
                Some((id, value)) if id == message => (value, 2),
                _ => (1, 1),
            };
            (
                durable_source.clone(),
                "s".to_owned(),
                message.clone(),
                format!("opencode:1:s:6:{message}"),
                T0 + index,
                value,
                revision,
            )
        })
        .collect();
    let decoded: Vec<Tuple> = observations
        .iter()
        .map(|record| {
            (
                record.source_id.clone(),
                record.session_id.clone(),
                record.message_id.clone(),
                record.record_id.clone(),
                record.occurred_at_ms,
                record.input.value.unwrap_or(u64::MAX),
                record.revision,
            )
        })
        .collect();
    assert_eq!(
        decoded, expected,
        "decoded pages: identities, times, values"
    );
    let durable: Vec<Tuple> = sql_rows(
        &history(data)?,
        "SELECT source_id, session_id, message_id, event_key, occurred_at_ms, \
         COALESCE(input_tokens, -1), revision FROM usage_events \
         ORDER BY occurred_at_ms, event_key",
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get::<_, i64>(5)?.cast_unsigned(),
                row.get::<_, i64>(6)?.cast_unsigned(),
            ))
        },
    )?;
    assert_eq!(
        durable, expected,
        "durable events: identities, times, values"
    );
    for record in &observations {
        let value = match edited {
            Some((id, value)) if record.message_id == id => value,
            _ => 1,
        };
        assert_eq!(
            values(record),
            [Some(value), Some(0), Some(0), Some(0), Some(0), Some(value)],
            "{}",
            record.message_id
        );
    }
    Ok(())
}

/// A completed database beyond the first 1,024 of the legacy terminal window is edited in place
/// after the generation stored it. No terminal attempt may certify the stale numbers: the change
/// is detected, the retry reads the edited database, and the final history carries it once.
#[test]
fn completed_database_beyond_the_legacy_window_is_revalidated_before_certification() -> TestResult {
    use quotern_core::ingest::fs::OpenKind;
    use quotern_core::snapshot::SourceSnapshot;
    const JOIN: &str = "SELECT m.relative_path, m.device, m.inode, m.size, m.mtime_ns, \
        p.identity, p.working_cursor_key FROM metadata_spool m JOIN opencode_progress p \
        ON p.source_id = m.source_id AND p.acquisition_path = m.relative_path \
        AND p.generation = m.generation WHERE m.source_id = ?1 AND m.generation = ?2 \
        AND m.parser_kind = 'sqlite' AND p.identity IS NOT NULL";
    type Completed = (String, i64, i64, i64, i64, String, Option<String>);
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(&directory.path().canonicalize()?)?;
    single_message_databases(&source)?;
    let fs = RecordingFs::new();
    let opened = Arc::new(std::sync::Mutex::new(Vec::<PathBuf>::new()));
    let log = Arc::clone(&opened);
    fs.on_boundary(move |kind, path| {
        if kind == OpenKind::Sqlite {
            log.lock().expect("open log").push(path.to_path_buf());
        }
    });
    let mut engine = open_recording_engine(fs.clone(), &source, &data, &home)
        .map_err(|report| format!("open failed: {report:?}"))?;
    let source_id: String = scalar(&data, "SELECT source_id FROM sources")?;
    let generation: i64 = scalar(&data, "SELECT generation FROM sources")?;
    let completed = |limit: Option<i64>| -> TestResult<Vec<Completed>> {
        let connection = history(&data)?;
        let row = |row: &rusqlite::Row<'_>| -> rusqlite::Result<Completed> {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        };
        Ok(match limit {
            Some(limit) => connection
                .prepare(&format!("{JOIN} LIMIT ?3"))?
                .query_map(rusqlite::params![source_id, generation, limit], row)?
                .collect::<rusqlite::Result<_>>()?,
            None => connection
                .prepare(JOIN)?
                .query_map(rusqlite::params![source_id, generation], row)?
                .collect::<rusqlite::Result<_>>()?,
        })
    };

    // Drive bounded passes until more than 1,024 databases are durably completed, short of all.
    let mut checkpoint = false;
    for pass in 0..64_i64 {
        let report = engine.pass(consented(), 1 + pass);
        assert_ne!(
            report.outcome,
            PassOutcome::Consistent,
            "pass {pass}: {report:?}"
        );
        assert_eq!(
            scalar::<i64>(&data, "SELECT generation FROM sources")?,
            generation
        );
        assert_eq!(
            scalar::<i64>(&data, "SELECT COUNT(*) FROM source_files")?,
            0
        );
        let joined = completed(None)?.len();
        if joined > 1_024 {
            assert!(
                joined < 1_089,
                "the checkpoint must precede the last database: {joined}"
            );
            checkpoint = true;
            break;
        }
    }
    assert!(
        checkpoint,
        "no durable checkpoint beyond 1,024 completed databases"
    );

    // Fixture targeting only: the victim lies outside the exact legacy first-1,024 window.
    let window: std::collections::BTreeSet<String> = completed(Some(1_024))?
        .into_iter()
        .map(|row| row.0)
        .collect();
    assert_eq!(window.len(), 1_024);
    let victim = completed(None)?
        .into_iter()
        .find(|row| {
            !window.contains(&row.0)
                && quotern_core::adapters::opencode::cursor_is_complete(row.6.as_deref())
                    == Ok(true)
        })
        .ok_or("no completed database outside the legacy window")?;
    let victim_path = source.join(&victim.0);
    let number = victim
        .0
        .trim_start_matches("opencode-")
        .trim_end_matches(".db");
    let id = format!("m-{number}");
    let staged: String = history(&data)?.query_row(
        "SELECT candidate_json FROM opencode_candidate_spool \
         WHERE source_id = ?1 AND generation = ?2 AND relative_path = ?3",
        rusqlite::params![source_id, generation, victim.0],
        |row| row.get(0),
    )?;
    let staged: Value = serde_json::from_str(&staged)?;
    assert_eq!(staged["message_id"], json!(id));
    assert_eq!(staged["components"]["input"], json!(1));
    assert_eq!(staged["total"], json!(1));
    let stamp = std::fs::metadata(&victim_path)?;
    assert_eq!(
        (
            i64::try_from(stamp.dev())?,
            i64::try_from(stamp.ino())?,
            i64::try_from(stamp.size())?
        ),
        (victim.1, victim.2, victim.3),
        "staged main-file witness"
    );
    assert_eq!(stamp.mtime() * 1_000_000_000 + stamp.mtime_nsec(), victim.4);
    let opens = || {
        opened
            .lock()
            .expect("open log")
            .iter()
            .filter(|path| **path == victim_path)
            .count()
    };
    let opens_at_edit = opens();
    assert_eq!(
        opens_at_edit, 1,
        "the victim was read exactly once and no reader remains"
    );

    // Edit the completed database in place: same inode, different main-file stamp.
    let edited = serde_json::to_vec(&json!({
        "role": "assistant",
        "tokens": counts(Some(9), Some(0), Some(0), Some(0), Some(0), Some(9)),
        "padding": "x".repeat(32_768)
    }))?;
    {
        let connection = Connection::open(&victim_path)?;
        connection.execute(
            "UPDATE message SET data = ?1 WHERE id = ?2",
            rusqlite::params![edited, id],
        )?;
    }
    let after = std::fs::metadata(&victim_path)?;
    assert_eq!(after.ino(), stamp.ino(), "edited in place");
    assert_ne!(after.size(), stamp.size(), "main-file stamp differs");

    // Every pass after the edit: a consistent report may only carry the edited number.
    let mut now = 1_000_000_i64;
    let mut changed = false;
    for step in 0..64 {
        let report = engine.pass(consented(), now);
        now += 400_000;
        let snapshot = SourceSnapshot::decode(&serde_json::to_vec(&engine.snapshot(&report)?)?)?;
        if report.outcome == PassOutcome::Consistent {
            assert_eq!(snapshot.projection.records, 1_089, "step {step}");
            assert_eq!(
                snapshot.projection.input.value,
                Some(1_097),
                "step {step}: terminal certification must include the edited completed database"
            );
            assert_eq!(snapshot.projection.total.value, Some(1_097));
            assert_database_consumers(&engine, &report, &data, Some((&id, 9)))?;
            break;
        }
        if report.failure == Some(FailureCode::SourceChanging) {
            assert_eq!(
                opens(),
                opens_at_edit,
                "the victim was not re-read before the terminal check"
            );
            assert_eq!(scalar::<i64>(&data, "SELECT dirty FROM sources")?, 1);
            assert_eq!(
                scalar::<i64>(&data, "SELECT generation FROM sources")?,
                generation,
                "no false generation completion"
            );
            changed = true;
            break;
        }
    }
    assert!(
        changed,
        "the terminal attempt never detected the edited database"
    );

    // Restart after the detected change and reacquire the stable fixture.
    drop(engine);
    let mut engine = open_recording_engine(fs.clone(), &source, &data, &home)
        .map_err(|report| format!("reopen failed: {report:?}"))?;
    let mut settled = None;
    for step in 0..80 {
        let report = engine.pass(consented(), now);
        now += 400_000;
        let snapshot = SourceSnapshot::decode(&serde_json::to_vec(&engine.snapshot(&report)?)?)?;
        if report.outcome == PassOutcome::Consistent {
            assert_eq!(snapshot.projection.input.value, Some(1_097), "step {step}");
            settled = Some(report);
            break;
        }
    }
    let settled = settled.ok_or("the stable fixture never reached a consistent generation")?;
    assert_eq!(settled.failure, None, "{settled:?}");
    assert_database_consumers(&engine, &settled, &data, Some((&id, 9)))?;
    let revisions = |data: &Path| -> TestResult<(i64, i64, i64, i64)> {
        Ok(history(data)?.query_row(
            "SELECT COUNT(*), SUM(input_tokens), SUM(total_tokens), SUM(revision) FROM usage_events",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?)
    };
    assert_eq!(revisions(&data)?, (1_089, 1_097, 1_097, 1_090));
    let victim_revision: i64 = history(&data)?.query_row(
        "SELECT revision FROM usage_events WHERE message_id = ?1",
        [&id],
        |row| row.get(0),
    )?;
    assert_eq!(victim_revision, 2);
    let projection: (i64, i64, i64) = history(&data)?.query_row(
        "SELECT records, input_sum, total_sum FROM source_projection_totals",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(projection, (1_089, 1_097, 1_097));
    assert_eq!(scalar::<i64>(&data, "SELECT dirty FROM sources")?, 0);

    // Repeating the stable acquisition adds no revision.
    let again = run_until_consistent(&mut engine, now, 80);
    let again = again.last().ok_or("pass")?;
    assert_eq!(again.outcome, PassOutcome::Consistent, "{again:?}");
    assert_database_consumers(&engine, again, &data, Some((&id, 9)))?;
    assert_eq!(revisions(&data)?, (1_089, 1_097, 1_097, 1_090));
    Ok(())
}

/// The sibling control at the same scale without any edit: the same bounded passes reach a
/// genuine consistent generation with exactly 1,089 records, so the invalidation above is not an
/// inability to terminate.
#[test]
fn unchanged_one_thousand_eighty_nine_databases_reach_an_exact_consistent_generation() -> TestResult
{
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(&directory.path().canonicalize()?)?;
    single_message_databases(&source)?;
    let mut engine = open_engine(&source, &data, &home)?;
    let reports = run_until_consistent(&mut engine, 1, 80);
    let last = reports.last().ok_or("pass")?;
    assert_eq!(last.outcome, PassOutcome::Consistent, "{last:?}");
    assert_eq!(last.failure, None, "{last:?}");
    assert_database_consumers(&engine, last, &data, None)?;
    let (records, input, total, revisions): (i64, i64, i64, i64) = history(&data)?.query_row(
        "SELECT COUNT(*), SUM(input_tokens), SUM(total_tokens), SUM(revision) FROM usage_events",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    assert_eq!(
        (records, input, total, revisions),
        (1_089, 1_089, 1_089, 1_089)
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Independent kernel-level M2 oracle (macOS arm64): effective descriptor access and mapping
// protection, never requested flags or production counters. The M1 `VfsProbe` above stays the
// separate requested-xOpen detector.
// ---------------------------------------------------------------------------------------------

/// The positive read-only predicate shared by the positive tests and the negative controls.
/// `samples` (live descriptors) are checked only when the reader is still alive.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn assert_m2_kernel_readonly(
    keys: &kernel::SourceKeys,
    samples: Option<&[kernel::FdSample]>,
    events: &kernel::Events,
) -> TestResult {
    events.checked()?;
    if let Some(samples) = samples {
        for kind in [kernel::DB, kernel::WAL, kernel::SHM] {
            assert!(
                samples.iter().any(|sample| sample.kind == kind),
                "no live descriptor of kind {kind}: {samples:?}"
            );
        }
        kernel::readonly_fd_oracle(samples)?;
        // The WAL is held through the VFS's own descriptor, which the parent's `open` never saw:
        // only the live sweep can prove it read-only. The mappings are still alive too, so the
        // kernel's present protection is asked again, not only the one at the call.
        assert!(events.opens_of(keys, kernel::WAL).is_empty(), "{events:?}");
        events.granted_map_oracle(keys, true)?;
    }
    assert!(!events.opens_of(keys, kernel::DB).is_empty(), "{events:?}");
    assert!(!events.opens_of(keys, kernel::SHM).is_empty(), "{events:?}");
    events.readonly_open_oracle(keys)?;
    let maps = events.maps_of(keys, kernel::SHM);
    assert!(
        !maps.is_empty(),
        "no successful SHM mapping observed: {events:?}"
    );
    assert!(
        maps.iter().all(|map| map.effective_protection.is_some()),
        "{maps:?}"
    );
    events.readonly_map_oracle(keys)?;
    println!(
        "M2 kernel: live descriptors {:?}; parent opens db={} shm={}; shm maps {:?}",
        samples.map(|samples| samples
            .iter()
            .map(|sample| (sample.kind, sample.access))
            .collect::<Vec<_>>()),
        events.opens_of(keys, kernel::DB).len(),
        events.opens_of(keys, kernel::SHM).len(),
        maps.iter()
            .map(|map| (map.requested_protection, map.effective_protection))
            .collect::<Vec<_>>()
    );
    Ok(())
}

/// Protection the kernel currently grants the writer's own (in-process) SHM region 0, reached
/// through the writer's `sqlite3_file` so the pointer is the very one a reader would reuse.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn writer_shm_protection(writer: &Connection) -> TestResult<std::ffi::c_int> {
    let mut file: *mut rusqlite::ffi::sqlite3_file = std::ptr::null_mut();
    // SAFETY: the connection is live; FILE_POINTER stores the main database's sqlite3_file.
    let code = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            writer.handle(),
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_FILE_POINTER,
            (&mut file as *mut *mut rusqlite::ffi::sqlite3_file).cast(),
        )
    };
    assert_eq!(code, rusqlite::ffi::SQLITE_OK);
    assert!(!file.is_null());
    // SAFETY: a live file has a method table; both pointers were checked.
    let methods_pointer = unsafe { (*file).pMethods };
    assert!(!methods_pointer.is_null());
    let map = unsafe { &*methods_pointer }
        .xShmMap
        .ok_or("writer lacks xShmMap")?;
    let mut pointer = std::ptr::null_mut();
    // SAFETY: region 0 of a WAL connection's wal-index; no extension is requested.
    let code = unsafe { map(file, 0, 32_768, 0, &mut pointer) };
    assert_eq!(code, rusqlite::ffi::SQLITE_OK);
    assert!(!pointer.is_null());
    Ok(kernel::map_protection(pointer, 32_768)?)
}

/// Actual-effect negative controls: the same predicates the positive tests use must turn red on a
/// really writable open, a really writable SHM mapping and a retained direct writable WAL
/// descriptor, each checked alone so one rejection cannot mask another.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn m2_kernel_oracle_rejects_writable_open_map_and_direct_wal_descriptor() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let database = directory.path().join("opencode.db");
    let mut writer = start_writer(&database)?;
    let keys = kernel::source_keys(&database)?;
    assert!(keys[kernel::DB].is_some() && keys[kernel::WAL].is_some());
    assert!(keys[kernel::SHM].is_some() && keys[kernel::JOURNAL].is_none());
    let wal = sidecar(&database, "-wal");
    let (db_bytes, wal_bytes) = (std::fs::read(&database)?, std::fs::read(&wal)?);

    // Writable open + writable map: an ordinary named Unix connection on the live database.
    let probe = kernel::SyscallProbe::start()?;
    let control = Connection::open_with_flags_and_vfs(
        &database,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        c"unix",
    )?;
    let rows: i64 = control.query_row("SELECT COUNT(*) FROM records", [], |row| row.get(0))?;
    assert_eq!(rows, 1);
    let samples = kernel::live_source_fds(&keys)?;
    let events = probe.events();
    assert!(events.errors.is_empty(), "{:?}", events.errors);

    assert!(
        samples
            .iter()
            .any(|sample| sample.kind == kernel::DB && sample.access == 2),
        "premise: the control holds a read-write database descriptor: {samples:?}"
    );
    let error = kernel::readonly_fd_oracle(&samples).expect_err("writable descriptor accepted");
    assert!(error.contains("writable source descriptor"), "{error}");
    assert!(
        events
            .opens_of(&keys, kernel::DB)
            .iter()
            .any(|event| event.access == 2),
        "the parent chain saw the writable open: {events:?}"
    );
    let error = events
        .readonly_open_oracle(&keys)
        .expect_err("writable open accepted");
    assert!(error.contains("writable source open"), "{error}");

    let maps = events.maps_of(&keys, kernel::SHM);
    assert!(
        maps.iter().any(|map| map
            .effective_protection
            .is_some_and(|protection| protection & kernel::PROT_WRITE != 0)),
        "premise: the kernel granted a writable SHM mapping: {maps:?}"
    );
    let error = events
        .readonly_map_oracle(&keys)
        .expect_err("writable mapping accepted");
    assert!(error.contains("writable shared-memory mapping"), "{error}");
    drop(control);
    probe.finish()?; // exact restoration of the saved open/mmap entries is verified here

    // A retained direct writable WAL descriptor never passes through the parent's `open`.
    let probe = kernel::SyscallProbe::start()?;
    let direct = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&wal)?;
    let samples = kernel::live_source_fds(&keys)?;
    assert!(
        samples
            .iter()
            .any(|sample| sample.kind == kernel::WAL && sample.access == 2),
        "{samples:?}"
    );
    let error = kernel::readonly_fd_oracle(&samples).expect_err("writable WAL accepted");
    assert!(error.contains("wal"), "{error}");
    let events = probe.finish()?;
    assert!(events.opens_of(&keys, kernel::WAL).is_empty(), "{events:?}");
    drop(direct);

    // After the controls and exact restoration, a fresh child-backed reader passes the same
    // predicates and the production hooks still read the live database.
    let probe = kernel::SyscallProbe::start()?;
    let reader = open_canonical(&database.canonicalize()?)?;
    reader.execute_batch("BEGIN")?;
    let rows: i64 = reader.query_row("SELECT COUNT(*) FROM records", [], |row| row.get(0))?;
    assert_eq!(rows, 1);
    let samples = kernel::live_source_fds(&keys)?;
    assert_m2_kernel_readonly(&keys, Some(&samples), &probe.events())?;
    reader.execute_batch("COMMIT")?;
    drop(reader);
    assert_m2_kernel_readonly(&keys, None, &probe.finish()?)?;
    assert_eq!(std::fs::read(&database)?, db_bytes);
    assert_eq!(std::fs::read(&wal)?, wal_bytes);
    writer.stop()?;
    Ok(())
}

/// A writable in-process SHM mapping is reused by SQLite's Unix VFS for any reader of the same
/// inode. Both orderings fail closed: the writer's mapping made before the probe (no new map
/// event can exist, so the kernel check of the writer's pointer is the premise) and made after it
/// (the probe sees a writable mapping and the read-only map predicate turns red).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn reused_writable_shared_memory_fails_closed_in_both_orderings() -> TestResult {
    for map_after_probe in [false, true] {
        let _guard = vfs_test_guard();
        let directory = tempdir()?;
        let (source, data, home) = source_roots(directory.path())?;
        let database = source.join("opencode.db");
        let make_writer = || -> TestResult<Connection> {
            let writer = open_fixture(&database)?;
            seed_wal_fixture(&writer)?;
            let mode: String = writer.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
            assert_eq!(mode, "wal");
            writer.pragma_update(None, "wal_autocheckpoint", 0)?;
            writer.execute("UPDATE message SET time_created = time_created", [])?;
            Ok(writer)
        };
        let (probe, writer) = if map_after_probe {
            let probe = kernel::SyscallProbe::start()?;
            (probe, make_writer()?)
        } else {
            let writer = make_writer()?;
            (kernel::SyscallProbe::start()?, writer)
        };
        let keys = kernel::source_keys(&database.canonicalize()?)?;
        assert!(keys[kernel::WAL].is_some() && keys[kernel::SHM].is_some());
        let premise = writer_shm_protection(&writer)?;
        assert_ne!(
            premise & kernel::PROT_WRITE,
            0,
            "premise: the writer's mapping is writable in the kernel (map_after_probe={map_after_probe})"
        );
        let image = source_image(&database)?;

        reset_vfs_metrics()?;
        let reader = open_canonical(&database.canonicalize()?)?;
        let error = reader
            .query_row("SELECT COUNT(*) FROM message", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect_err("a writable in-process SHM mapping was reused");
        assert!(
            matches!(error, rusqlite::Error::SqliteFailure(..)),
            "{error:?}"
        );
        drop(reader);
        let metrics = vfs_metrics()?;
        assert!(
            metrics.writable_shared_memory_maps_rejected
                + metrics.unverified_shared_memory_maps_rejected
                > 0,
            "{metrics:?}"
        );
        assert_eq!(metrics.readonly_shared_memory_maps, 0, "{metrics:?}");
        assert_source_unchanged(&database, &image)?;

        let mut engine = open_engine(&source, &data, &home)?;
        let report = engine.pass(consented(), 1);
        assert_eq!(report.outcome, PassOutcome::Unavailable, "{report:?}");
        assert_eq!(report.failure, Some(FailureCode::Sqlite), "{report:?}");
        assert_eq!(report.records_committed, 0);
        assert!(engine.observations()?.is_empty());
        assert_source_unchanged(&database, &image)?;

        let events = probe.finish()?;
        let maps = events.maps_of(&keys, kernel::SHM);
        if map_after_probe {
            assert!(
                maps.iter().any(|map| map
                    .effective_protection
                    .is_some_and(|protection| protection & kernel::PROT_WRITE != 0)),
                "the probe saw the writer's writable SHM mapping: {events:?}"
            );
            let error = events
                .readonly_map_oracle(&keys)
                .expect_err("writable reused mapping accepted");
            assert!(error.contains("writable shared-memory mapping"), "{error}");
        } else {
            // The mapping predates the probe: no new map event exists, so the probe alone proves
            // neither a read-only reuse nor the absence of a writable one. The kernel premise
            // above and the fail-closed pass are the evidence.
            assert!(maps.is_empty(), "{maps:?}");
        }
        drop(engine);
        drop(writer);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Cached shared-memory identity, requested versus granted protection, bounded probe and
// restoration, and refused opens.
// ---------------------------------------------------------------------------------------------

/// SQLite's Unix VFS shares one shared-memory node per database inode inside a process, so a
/// second reader never opens or stats the sidecar: a path check cannot vouch for what it maps.
/// The mapping itself must be bound to the inode the sidecar path names now.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn cached_readonly_shared_memory_is_bound_to_the_sidecar_inode() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let (source, data, home) = source_roots(directory.path())?;
    let database = source.join("opencode.db");
    let mut writer = start_writer(&database)?;
    let canonical = database.canonicalize()?;
    let shm = sidecar(&canonical, "-shm");
    let (db_bytes, wal_bytes) = (
        std::fs::read(&canonical)?,
        std::fs::read(sidecar(&canonical, "-wal"))?,
    );
    let original = kernel::source_keys(&canonical)?;
    let probe = kernel::SyscallProbe::start()?;
    reset_vfs_metrics()?;
    let count = |connection: &Connection| -> rusqlite::Result<i64> {
        connection.query_row("SELECT COUNT(*) FROM records", [], |row| row.get(0))
    };

    // The first reader opens and maps the sidecar and keeps its node alive.
    let first = open_canonical(&canonical)?;
    first.execute_batch("BEGIN")?;
    assert_eq!(count(&first)?, 1);
    let shm_opens = probe.events().opens_of(&original, kernel::SHM).len();
    assert_eq!(shm_opens, 1, "the first reader opens the sidecar once");

    // A second reader reuses the cached node with the sidecar unchanged: accepted, with no new
    // open of the sidecar at all (the premise that a pathname check could never see anything).
    let second = open_canonical(&canonical)?;
    second.execute_batch("BEGIN")?;
    assert_eq!(count(&second)?, 1);
    let events = probe.events();
    assert_eq!(events.opens_of(&original, kernel::SHM).len(), shm_opens);
    let accepted = vfs_metrics()?;
    assert!(accepted.readonly_shared_memory_maps >= 2, "{accepted:?}");
    assert_eq!(accepted.shared_memory_identity_rejected, 0, "{accepted:?}");
    second.execute_batch("COMMIT")?;
    drop(second);

    // The sidecar path now names a different inode holding identical bytes.
    let parked = sidecar(&canonical, "-shm.parked");
    std::fs::rename(&shm, &parked)?;
    std::fs::copy(&parked, &shm)?;
    let replaced = kernel::source_keys(&canonical)?;
    assert_ne!(
        replaced[kernel::SHM],
        original[kernel::SHM],
        "premise: new inode"
    );
    let kernel_bytes = std::fs::read(&shm)?;
    assert_eq!(kernel_bytes, std::fs::read(&parked)?, "premise: same bytes");

    let reader_rejected = match open_canonical(&canonical) {
        Err(_) => true,
        Ok(reader) => count(&reader).is_err(),
    };
    assert!(
        reader_rejected,
        "a cached mapping of the replaced sidecar was served"
    );
    let rejected = vfs_metrics()?;
    assert!(rejected.shared_memory_identity_rejected > 0, "{rejected:?}");
    assert_eq!(
        rejected.readonly_shared_memory_maps,
        accepted.readonly_shared_memory_maps
    );
    let events = probe.events();
    assert_eq!(
        events.opens_of(&original, kernel::SHM).len(),
        shm_opens,
        "the rejection happened with no open of the sidecar, on the cached node alone"
    );

    // The engine consumer fails closed the same way: nothing published, source untouched.
    let mut engine = open_engine(&source, &data, &home)?;
    let report = engine.pass(consented(), 1);
    assert_eq!(report.outcome, PassOutcome::Unavailable, "{report:?}");
    assert_eq!(report.failure, Some(FailureCode::Sqlite), "{report:?}");
    assert_eq!(report.records_committed, 0);
    assert!(engine.observations()?.is_empty());
    assert_eq!(std::fs::read(&canonical)?, db_bytes);
    assert_eq!(std::fs::read(sidecar(&canonical, "-wal"))?, wal_bytes);

    // With the original inode back at the path the cached node is bound again and read.
    std::fs::remove_file(&shm)?;
    std::fs::rename(&parked, &shm)?;
    assert_eq!(kernel::source_keys(&canonical)?, original);
    let report = engine.pass(consented(), 2);
    assert_eq!(report.outcome, PassOutcome::Consistent, "{report:?}");
    assert_eq!(report.records_committed, 1, "{report:?}");
    drop(engine);

    first.execute_batch("COMMIT")?;
    drop(first);
    let events = probe.finish()?;
    events.readonly_open_oracle(&original)?;
    events.requested_map_oracle(&original)?;
    writer.stop()?;
    Ok(())
}

/// Requested and granted protection are separate facts. A mapping requested read-only on a
/// writable descriptor is granted read-only and then raised by the kernel's own `mprotect`: only
/// the live granted-protection oracle sees it. A mapping requested writable is red on both. A
/// read-only descriptor cannot be mapped writable at all, and its mapping cannot be raised.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn requested_and_granted_shared_memory_protection_are_separately_discriminated() -> TestResult {
    use std::os::fd::AsRawFd;

    const MAP_SHARED: std::ffi::c_int = 1;
    const EACCES: std::ffi::c_int = 13;
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let database = directory.path().join("opencode.db");
    let mut writer = start_writer(&database)?;
    let keys = kernel::source_keys(&database)?;
    let shm = sidecar(&database, "-shm");
    let length = 32_768;
    let writable_descriptor = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&shm)?;
    let readonly_descriptor = std::fs::File::open(&shm)?;
    let probe = kernel::SyscallProbe::start()?;

    let (address, errno) = probe.mmap(
        length,
        kernel::PROT_READ,
        MAP_SHARED,
        writable_descriptor.as_raw_fd(),
        0,
    )?;
    assert_ne!(address, usize::MAX, "errno {errno}");
    let events = probe.events();
    events.requested_map_oracle(&keys)?;
    events.granted_map_oracle(&keys, true)?;

    // The kernel raises the protection of a mapping that was requested read-only.
    kernel::set_protection(
        address as *mut _,
        length,
        kernel::PROT_READ | kernel::PROT_WRITE,
    )
    .map_err(|errno| format!("mprotect: errno {errno}"))?;
    assert_ne!(
        kernel::map_protection(address as *mut _, length)? & kernel::PROT_WRITE,
        0,
        "premise: the kernel now grants write"
    );
    events.requested_map_oracle(&keys)?;
    events.granted_map_oracle(&keys, false)?; // the grant at the call was read-only
    let error = events
        .granted_map_oracle(&keys, true)
        .expect_err("a raised protection was accepted");
    assert!(error.contains("granted"), "{error}");

    // A mapping requested writable is red on the request and on the grant.
    let (writable, errno) = probe.mmap(
        length,
        kernel::PROT_READ | kernel::PROT_WRITE,
        MAP_SHARED,
        writable_descriptor.as_raw_fd(),
        0,
    )?;
    assert_ne!(writable, usize::MAX, "errno {errno}");
    let events = probe.events();
    let error = events
        .requested_map_oracle(&keys)
        .expect_err("writable request accepted");
    assert!(error.contains("requested"), "{error}");
    assert!(events.maps.iter().any(|map| map.address == writable
        && map.effective_protection == Some(kernel::PROT_READ | kernel::PROT_WRITE)));

    // The read-only descriptor: the kernel refuses a writable shared mapping, the callback hands
    // the failure back with its errno and records nothing; a read-only mapping cannot be raised.
    let recorded = probe.events().maps.len();
    let (refused, errno) = probe.mmap(
        length,
        kernel::PROT_READ | kernel::PROT_WRITE,
        MAP_SHARED,
        readonly_descriptor.as_raw_fd(),
        0,
    )?;
    assert_eq!((refused, errno), (usize::MAX, EACCES));
    assert_eq!(probe.events().maps.len(), recorded);
    let (readonly, errno) = probe.mmap(
        length,
        kernel::PROT_READ,
        MAP_SHARED,
        readonly_descriptor.as_raw_fd(),
        0,
    )?;
    assert_ne!(readonly, usize::MAX, "errno {errno}");
    assert_eq!(
        kernel::set_protection(
            readonly as *mut _,
            length,
            kernel::PROT_READ | kernel::PROT_WRITE
        ),
        Err(EACCES)
    );
    assert_eq!(
        kernel::map_protection(readonly as *mut _, length)? & kernel::PROT_WRITE,
        0
    );

    for mapped in [address, writable, readonly] {
        kernel::unmap(mapped as *mut _, length)
            .map_err(|errno| format!("munmap: errno {errno}"))?;
    }
    probe.finish()?;
    writer.stop()?;
    Ok(())
}

/// Every retained buffer of the probe is bounded; the cap'th event is kept, the next one is
/// dropped and recorded as a sticky overflow that fails `finish` and every oracle; the callbacks
/// hand back the parent's exact return value and `errno`; and the exact saved entries come back.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn kernel_probe_state_is_bounded_with_exact_returns_and_restoration() -> TestResult {
    use std::ffi::{CString, c_int};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    const MAP_PRIVATE: c_int = 2;
    const ENOENT: c_int = 2;
    const EBADF: c_int = 9;
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let scratch = directory.path().join("scratch.bin");
    std::fs::write(&scratch, [0_u8; 4096])?;
    let path = CString::new(scratch.to_str().ok_or("path")?)?;
    let absent = CString::new(directory.path().join("absent").to_str().ok_or("path")?)?;
    let keys: kernel::SourceKeys = [None; 4];
    // The permanent production hooks go into the table the first time any probe (or reader)
    // starts: the baseline restoration is held to is the table with them, in a fresh process too.
    kernel::initialize_production_hooks()?;
    let saved = kernel::SyscallProbe::table()?;
    let limits = |opens, maps, fstat_failures, errors| kernel::Limits {
        opens,
        maps,
        fstat_failures,
        open_failures: opens,
        errors,
    };

    let close = |fd: c_int| drop(unsafe { OwnedFd::from_raw_fd(fd) });
    let open = |probe: &kernel::SyscallProbe| -> TestResult<c_int> {
        let (fd, errno) = probe.open(&path, 0, 0)?;
        assert!(fd >= 0 && errno == 0, "fd {fd}, errno {errno}");
        Ok(fd)
    };
    let overflow_ends_in_failure = |probe: kernel::SyscallProbe| -> TestResult {
        let events = probe.events();
        assert!(events.overflowed);
        assert!(events.checked().is_err());
        assert!(events.readonly_open_oracle(&keys).is_err());
        assert!(events.requested_map_oracle(&keys).is_err());
        assert!(events.granted_map_oracle(&keys, false).is_err());
        let error = probe.finish().expect_err("an overflowed probe finished");
        assert!(error.contains("overflow"), "{error}");
        assert_eq!(kernel::SyscallProbe::table()?, saved, "exact restoration");
        Ok(())
    };

    // Opens: cap kept, cap + 1 dropped, the returned descriptor and errno still exact.
    let probe = kernel::SyscallProbe::start_with(limits(3, 3, 3, 3))?;
    assert_ne!(kernel::SyscallProbe::table()?, saved);
    for _ in 0..3 {
        close(open(&probe)?);
    }
    let events = probe.events();
    assert_eq!((events.opens.len(), events.overflowed), (3, false));
    events.checked()?;
    let fd = open(&probe)?; // cap + 1
    close(fd);
    assert_eq!(probe.events().opens.len(), 3);
    // A failing open: the exact -1 and ENOENT, counted, and its errno kept.
    assert_eq!(probe.open(&absent, 0, 0)?, (-1, ENOENT));
    let failures = probe.events().open_failures;
    assert_eq!(probe.events().failed_opens, 1);
    assert!(
        matches!(
            failures[..],
            [kernel::OpenFailure {
                errno: ENOENT,
                foreign: false
            }]
        ),
        "{failures:?}"
    );
    overflow_ends_in_failure(probe)?;

    // Maps.
    let probe = kernel::SyscallProbe::start_with(limits(8, 2, 3, 3))?;
    let file = std::fs::File::open(&scratch)?;
    let mut mapped = Vec::new();
    for round in 0..3 {
        let (address, errno) =
            probe.mmap(4096, kernel::PROT_READ, MAP_PRIVATE, file.as_raw_fd(), 0)?;
        assert_ne!(address, usize::MAX, "errno {errno}");
        mapped.push(address);
        let events = probe.events();
        assert_eq!(events.overflowed, round == 2, "round {round}");
        assert_eq!(events.maps.len(), (round + 1).min(2));
    }
    for address in mapped {
        kernel::unmap(address as *mut _, 4096).map_err(|errno| format!("errno {errno}"))?;
    }
    overflow_ends_in_failure(probe)?;

    // Failing fstat entries: exact -1 / EBADF, cap kept, cap + 1 dropped.
    let probe = kernel::SyscallProbe::start_with(limits(8, 8, 2, 3))?;
    assert_eq!(probe.fstat(file.as_raw_fd())?.0, 0);
    for round in 0..3 {
        assert_eq!(probe.fstat(-1)?, (-1, EBADF));
        let events = probe.events();
        assert_eq!(events.overflowed, round == 2, "round {round}");
        assert_eq!(events.fstat_failures.len(), (round + 1).min(2));
    }
    assert!(
        probe
            .events()
            .fstat_failures
            .iter()
            .all(|f| f.errno == EBADF && f.fd == -1)
    );
    overflow_ends_in_failure(probe)?;

    // Observation errors: a map of a bad descriptor records a fault and still returns the
    // kernel's failure with its errno.
    let probe = kernel::SyscallProbe::start_with(limits(8, 8, 8, 2))?;
    for round in 0..3 {
        let (address, errno) = probe.mmap(4096, kernel::PROT_READ, MAP_PRIVATE, 1_000_000, 0)?;
        assert_eq!((address, errno), (usize::MAX, EBADF));
        let events = probe.events();
        assert_eq!(events.overflowed, round == 2, "round {round}");
        assert_eq!(events.errors.len(), (round + 1).min(2));
    }
    assert!(probe.events().errors.iter().all(|fault| matches!(
        fault,
        kernel::Fault::Fstat {
            fd: 1_000_000,
            errno: EBADF
        }
    )));
    overflow_ends_in_failure(probe)?;

    // Unwinding while armed restores the exact entries (Drop is the backstop).
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _probe = kernel::SyscallProbe::start().expect("start");
        assert_ne!(kernel::SyscallProbe::table().expect("table"), saved);
        panic!("unwinding while the probe is armed");
    }));
    assert!(unwound.is_err());
    assert_eq!(
        kernel::SyscallProbe::table()?,
        saved,
        "restored after unwind"
    );

    // Another thread's events are kept, marked foreign, and evaluated like any other.
    let database = directory.path().join("foreign.db");
    drop(Connection::open(&database)?);
    let keys = kernel::source_keys(&database)?;
    let probe = kernel::SyscallProbe::start()?;
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                Connection::open_with_flags_and_vfs(
                    &database,
                    OpenFlags::SQLITE_OPEN_READ_WRITE,
                    c"unix",
                )
                .map(drop)
            })
            .join()
            .expect("foreign thread")
    })?;
    let events = probe.events();
    assert!(
        events
            .opens_of(&keys, kernel::DB)
            .iter()
            .all(|event| event.foreign),
        "{events:?}"
    );
    let error = events
        .readonly_open_oracle(&keys)
        .expect_err("a foreign writable open was accepted");
    assert!(error.contains("writable source open"), "{error}");
    let before = probe.events().opens.len();
    drop(Connection::open_with_flags_and_vfs(
        &database,
        OpenFlags::SQLITE_OPEN_READ_ONLY,
        c"unix",
    )?);
    let events = probe.events();
    assert!(events.opens[before..].iter().all(|event| !event.foreign));

    // A foreign thread's mapping and failing `fstat` through the installed entries are kept and
    // marked foreign too, and the owner's own calls are not.
    let mapped_file = std::fs::File::open(&scratch)?;
    let mapped_fd = mapped_file.as_raw_fd();
    let (maps_before, failures_before) = {
        let events = probe.events();
        (events.maps.len(), events.fstat_failures.len())
    };
    std::thread::scope(|scope| {
        scope
            .spawn(|| -> Result<(), String> {
                let (address, errno) =
                    kernel::call_mmap(4096, kernel::PROT_READ, MAP_PRIVATE, mapped_fd, 0)?;
                if address == usize::MAX {
                    return Err(format!("foreign map failed: errno {errno}"));
                }
                kernel::unmap(address as *mut _, 4096).map_err(|errno| format!("errno {errno}"))?;
                match kernel::call_fstat(-1)? {
                    (-1, EBADF) => Ok(()),
                    other => Err(format!("foreign fstat of -1: {other:?}")),
                }
            })
            .join()
            .expect("foreign thread")
    })?;
    let events = probe.events();
    let (foreign_maps, foreign_failures) = (
        &events.maps[maps_before..],
        &events.fstat_failures[failures_before..],
    );
    assert!(
        !foreign_maps.is_empty() && foreign_maps.iter().all(|map| map.foreign),
        "{foreign_maps:?}"
    );
    assert!(
        !foreign_failures.is_empty()
            && foreign_failures
                .iter()
                .all(|failure| failure.foreign && failure.errno == EBADF && failure.fd == -1),
        "{foreign_failures:?}"
    );
    let (maps_before, failures_before) = (events.maps.len(), events.fstat_failures.len());
    let (address, errno) = probe.mmap(4096, kernel::PROT_READ, MAP_PRIVATE, mapped_fd, 0)?;
    assert_ne!(address, usize::MAX, "errno {errno}");
    kernel::unmap(address as *mut _, 4096).map_err(|errno| format!("errno {errno}"))?;
    assert_eq!(probe.fstat(-1)?, (-1, EBADF));
    let events = probe.events();
    assert!(
        events.maps.len() > maps_before
            && events.maps[maps_before..].iter().all(|map| !map.foreign),
        "{events:?}"
    );
    assert!(
        events.fstat_failures.len() > failures_before
            && events.fstat_failures[failures_before..]
                .iter()
                .all(|failure| !failure.foreign),
        "{events:?}"
    );
    probe.finish()?;
    assert_eq!(kernel::SyscallProbe::table()?, saved);
    Ok(())
}

/// Failed-open receipts have their own ceiling. On a fresh probe in which no other buffer can
/// overflow, real refused opens of an absent path fill it to the cap and keep every receipt, the
/// next one is dropped but counted and fails the observation, every oracle and `finish`, the exact
/// `-1`/`ENOENT` comes back each time, and the entries are restored. Owner and foreign threads
/// are controls of each other, and receipts keep the thread that made each call.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn failed_open_receipts_are_bounded_with_owner_and_foreign_controls() -> TestResult {
    use std::ffi::{CString, c_int};

    const ENOENT: c_int = 2;
    const CAP: usize = 3;
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let absent = CString::new(directory.path().join("absent").to_str().ok_or("path")?)?;
    let keys: kernel::SourceKeys = [None; 4];
    kernel::initialize_production_hooks()?;
    let saved = kernel::SyscallProbe::table()?;
    let fresh = || {
        kernel::SyscallProbe::start_with(kernel::Limits {
            opens: 8,
            maps: 8,
            fstat_failures: 8,
            open_failures: CAP,
            errors: 8,
        })
    };
    // One refused open, made by the arming thread or by another one.
    let refuse = |probe: &kernel::SyscallProbe, foreign: bool| -> TestResult<(c_int, c_int)> {
        if foreign {
            let call = std::thread::scope(|scope| {
                scope
                    .spawn(|| kernel::call_open(&absent, kernel::O_RDONLY, 0))
                    .join()
                    .expect("foreign open")
            });
            Ok(call?)
        } else {
            Ok(probe.open(&absent, kernel::O_RDONLY, 0)?)
        }
    };

    for foreign in [false, true] {
        let probe = fresh()?;
        for _ in 0..CAP {
            assert_eq!(refuse(&probe, foreign)?, (-1, ENOENT), "foreign {foreign}");
        }
        let events = probe.events();
        assert_eq!(
            (
                events.open_failures.len(),
                events.failed_opens,
                events.overflowed
            ),
            (CAP, CAP, false),
            "foreign {foreign}: {events:?}"
        );
        assert!(
            events
                .open_failures
                .iter()
                .all(|failure| failure.errno == ENOENT && failure.foreign == foreign),
            "foreign {foreign}: {events:?}"
        );
        assert!(
            events.opens.is_empty() && events.maps.is_empty() && events.errors.is_empty(),
            "{events:?}"
        );
        events.checked()?;
        events.readonly_open_oracle(&keys)?;
        events.requested_map_oracle(&keys)?;
        events.granted_map_oracle(&keys, false)?;
        events.readonly_map_oracle(&keys)?;

        // cap + 1: dropped, counted, and everything that consumes the receipts says so.
        assert_eq!(refuse(&probe, foreign)?, (-1, ENOENT), "foreign {foreign}");
        let events = probe.events();
        assert_eq!(
            (
                events.open_failures.len(),
                events.failed_opens,
                events.overflowed
            ),
            (CAP, CAP + 1, true),
            "foreign {foreign}: {events:?}"
        );
        assert!(events.checked().is_err());
        assert!(events.readonly_open_oracle(&keys).is_err());
        assert!(events.requested_map_oracle(&keys).is_err());
        assert!(events.granted_map_oracle(&keys, false).is_err());
        assert!(events.readonly_map_oracle(&keys).is_err());
        let error = probe.finish().expect_err("an overflowed probe finished");
        assert!(error.contains("overflow"), "{error}");
        assert_eq!(kernel::SyscallProbe::table()?, saved, "exact restoration");
    }

    // Each receipt keeps the thread that made its call.
    let probe = fresh()?;
    let made_by = [false, true, false];
    for foreign in made_by {
        assert_eq!(refuse(&probe, foreign)?, (-1, ENOENT));
    }
    let events = probe.finish()?;
    let attributed: Vec<_> = events.open_failures.iter().map(|f| f.foreign).collect();
    assert_eq!(attributed, made_by, "{events:?}");
    assert_eq!(kernel::SyscallProbe::table()?, saved);
    Ok(())
}

/// A refusal made before the kernel runs leaves `errno` as an earlier call left it. SQLite's
/// `robust_open` retries an `open` that fails with `EINTR` without bound, so a refused open must
/// set its own non-retryable `errno`: the probe plants `EINTR` right before every open of the
/// parent and the sweep refuses each possible open of a source read in turn.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn refused_opens_leave_a_non_retryable_errno() -> TestResult {
    use quotern_core::ingest::sqlite_ro::MetadataMeter;

    const EINTR: std::ffi::c_int = 4;
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let database = directory.path().join("opencode.db");
    let mut writer = start_writer(&database)?;
    let canonical = database.canonicalize()?;
    let read = |allowance: u32| -> (u32, bool, bool) {
        let meter = MetadataMeter::begin(allowance);
        let rows = open_canonical(&canonical).ok().and_then(|connection| {
            connection
                .query_row("SELECT COUNT(*) FROM records", [], |row| {
                    row.get::<_, i64>(0)
                })
                .ok()
        });
        let (used, refused) = meter.state();
        (used, refused, rows.is_some())
    };
    read(10_000); // first-use initialisation
    let probe = kernel::SyscallProbe::start_stale_errno(EINTR)?;
    let (total, refused, rows) = read(10_000);
    assert!(!refused && rows, "{total} {refused} {rows}");
    for allowance in 0..total {
        let (_, refused, _) = read(allowance);
        assert!(refused, "allowance {allowance} of {total}");
    }
    let events = probe.finish()?;
    assert!(
        events.failed_opens > 0,
        "premise: some allowance refused an open"
    );
    writer.stop()?;
    Ok(())
}

/// A refused first map leaves the connection without a node, so its next map opens the sidecar
/// again and must be validated again: a swap at the instant of that second open is refused too.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn a_shared_memory_map_refused_once_is_validated_again_on_retry() -> TestResult {
    use quotern_core::ingest::sqlite_ro::set_open_hook;

    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let database = directory.path().join("opencode.db");
    let mut writer = start_writer(&database)?;
    let canonical = database.canonicalize()?;
    let shm = sidecar(&canonical, "-shm");
    let swaps = std::rc::Rc::new(std::cell::Cell::new(0_u32));
    let (hook_swaps, hook_shm) = (std::rc::Rc::clone(&swaps), shm.clone());
    // Each open of the sidecar finds another inode with identical bytes at the path, put there
    // between the check of the path and the kernel's open.
    set_open_hook(Some(Box::new(move |path| {
        let _ = hook_swaps.get();
        if path == hook_shm {
            let round = hook_swaps.get() + 1;
            hook_swaps.set(round);
            let parked = sidecar(&hook_shm, &format!(".parked{round}"));
            std::fs::rename(&hook_shm, &parked).expect("park the sidecar");
            std::fs::copy(&parked, &hook_shm).expect("replace the sidecar");
        }
    })));
    reset_vfs_metrics()?;
    let reader = open_canonical(&canonical)?;
    let count = || -> rusqlite::Result<i64> {
        reader.query_row("SELECT COUNT(*) FROM records", [], |row| row.get(0))
    };
    assert!(count().is_err(), "the first open was swapped and refused");
    assert_eq!(swaps.get(), 1);
    assert!(
        count().is_err(),
        "the retry opened the sidecar again without being validated again"
    );
    assert_eq!(swaps.get(), 2, "the retry did open the sidecar again");
    let metrics = vfs_metrics()?;
    assert!(metrics.opens_refused >= 2, "{metrics:?}");
    set_open_hook(None);
    drop(reader);
    writer.stop()?;
    Ok(())
}

/// A sweep that fails after others succeeded is a failed proof, not a smaller successful one. The
/// failure is a real one: the real sweep meets a descriptor that is still open (`F_GETFL`
/// succeeds) and that the kernel refuses to describe (`fstat` fails), keeps that error, and the
/// proof built from the sweeps is rejected.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn a_failed_descriptor_sweep_among_successes_fails_the_wal_access_proof() -> TestResult {
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let database = directory.path().join("opencode.db");
    let mut writer = start_writer(&database)?;
    let canonical = database.canonicalize()?;
    let keys = kernel::source_keys(&canonical)?;
    let shm = sidecar(&canonical, "-shm");
    // Each reader is the only one in this process, so each one opens the sidecar again.
    let read_once = || -> TestResult {
        let reader = open_canonical(&canonical)?;
        let rows: i64 = reader.query_row("SELECT COUNT(*) FROM records", [], |row| row.get(0))?;
        assert_eq!(rows, 1);
        Ok(())
    };

    // Control: two successful sweeps make a complete proof.
    let all_good = Sweeps::default();
    sweep_on_shm_open(
        keys,
        shm.clone(),
        Sweeps::clone(&all_good),
        kernel::live_source_fds,
    );
    read_once()?;
    read_once()?;
    quotern_core::ingest::sqlite_ro::set_open_hook(None);
    assert_eq!(all_good.borrow().samples.len(), 2);
    all_good.borrow().complete()?;

    // One success, then the real sweep meets a descriptor it cannot inspect while it is open: the
    // failure is retained and fails the proof.
    let mixed = Sweeps::default();
    sweep_on_shm_open(keys, shm, Sweeps::clone(&mixed), kernel::live_source_fds);
    read_once()?;
    let revoked = kernel::RevokedDescriptor::new()?;
    read_once()?;
    quotern_core::ingest::sqlite_ro::set_open_hook(None);
    let mixed = mixed.borrow();
    assert_eq!((mixed.samples.len(), mixed.failures.len()), (1, 1));
    let expected = format!("fstat {}: errno 9", revoked.fd());
    assert_eq!(mixed.failures, std::slice::from_ref(&expected));
    let error = mixed
        .complete()
        .expect_err("a failed sweep among successes passed");
    assert!(error.to_string().contains(&expected), "{error}");
    drop(revoked);
    writer.stop()?;
    Ok(())
}

/// A descriptor that another thread closes between the sweep's checks is not a descriptor of the
/// instant and is skipped, whichever check it falls between; it must neither hide a descriptor
/// that is still open and cannot be inspected, nor remove a descriptor that is still open.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn a_descriptor_closed_between_the_sweeps_checks_is_skipped_and_hides_no_open_failure() -> TestResult
{
    use std::os::fd::{AsRawFd, OwnedFd};

    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let database = directory.path().join("closing.db");
    std::fs::write(&database, [0_u8; 16])?;
    let keys = kernel::source_keys(&database)?;
    let held = std::fs::File::open(&database)?;
    let open_closing = || -> TestResult<Option<OwnedFd>> {
        Ok(Some(OwnedFd::from(std::fs::File::open(&database)?)))
    };

    for gap in [kernel::Gap::BeforeMetadata, kernel::Gap::BeforeAccess] {
        let mut closing = open_closing()?;
        let target = closing
            .as_ref()
            .map(AsRawFd::as_raw_fd)
            .ok_or("descriptor")?;
        let mut closed = 0;
        let samples = kernel::live_source_fds_between(&keys, &mut |at, fd| {
            if at == gap && fd == target {
                closed += 1;
                drop(closing.take());
            }
        })?;
        assert_eq!(closed, 1, "{gap:?}");
        let fds: Vec<_> = samples.iter().map(|sample| sample.fd).collect();
        assert_eq!(fds, [held.as_raw_fd()], "{gap:?}: {samples:?}");
    }

    // The closed descriptor comes first (lower number) and is skipped; the one after it is still
    // open, cannot be described, and is reported.
    let mut closing = open_closing()?;
    let revoked = kernel::RevokedDescriptor::new()?;
    let target = closing
        .as_ref()
        .map(AsRawFd::as_raw_fd)
        .ok_or("descriptor")?;
    if revoked.fd() < target {
        return Err(format!("premise: descriptor order {} < {target}", revoked.fd()).into());
    }
    let mut closed = 0;
    let error = kernel::live_source_fds_between(&keys, &mut |at, fd| {
        if at == kernel::Gap::BeforeMetadata && fd == target {
            closed += 1;
            drop(closing.take());
        }
    })
    .expect_err("a closed descriptor hid a descriptor that is still open and failing");
    assert_eq!(closed, 1);
    assert_eq!(error, format!("fstat {}: errno 9", revoked.fd()));
    drop(revoked);
    let samples = kernel::live_source_fds(&keys)?;
    assert_eq!(
        samples.iter().map(|sample| sample.fd).collect::<Vec<_>>(),
        [held.as_raw_fd()]
    );
    Ok(())
}

/// A FIFO that holds a native `open` inside the kernel until the test opens its other end, so a
/// probe callback can be kept running deterministically.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct Gate {
    path: PathBuf,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Gate {
    fn new(directory: &Path) -> TestResult<Self> {
        let path = directory.join("gate");
        mkfifo(&path)?;
        Ok(Self { path })
    }

    /// Opens the write end, which lets the blocked read-end open return.
    fn release(&self) -> std::io::Result<()> {
        std::fs::OpenOptions::new()
            .write(true)
            .open(&self.path)
            .map(drop)
    }

    /// Best-effort release for an unwinding test: never blocks (`ENXIO` without a reader).
    fn unblock(&self) {
        use std::os::unix::fs::OpenOptionsExt;
        const O_NONBLOCK: i32 = 4;
        let _ = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(O_NONBLOCK)
            .open(&self.path);
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct Unblock<'a>(&'a Gate);

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Drop for Unblock<'_> {
    fn drop(&mut self) {
        self.0.unblock();
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn wait_until(what: &str, mut ready: impl FnMut() -> bool) -> TestResult {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !ready() {
        if std::time::Instant::now() > deadline {
            return Err(format!("timed out waiting for {what}").into());
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    Ok(())
}

/// Restoring a probe while another thread's callback is still inside the parent's `open` waits
/// for it: the call returns its own descriptor and `errno`, and its event is in the result,
/// attributed to the foreign thread, not lost to a restoration that already took the state.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn restoring_a_probe_waits_for_a_running_foreign_callback_and_keeps_its_event() -> TestResult {
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::fs::MetadataExt;

    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let gate = Gate::new(directory.path())?;
    let path = std::ffi::CString::new(gate.path.to_str().ok_or("path")?)?;
    kernel::initialize_production_hooks()?;
    let saved = kernel::SyscallProbe::table()?;
    let probe = kernel::SyscallProbe::start()?;
    probe.set_quiescence(std::time::Duration::from_secs(60));

    let (events, (fd, errno)) = std::thread::scope(|scope| -> TestResult<_> {
        let _unblock = Unblock(&gate);
        let foreign = scope.spawn(|| kernel::call_open(&path, kernel::O_RDONLY, 0));
        wait_until("the foreign open to be running", || {
            kernel::callbacks_in_flight() == 1
        })?;
        // Opens the write end only once restoration is waiting for the callback.
        let releaser = scope.spawn(|| -> Result<(), String> {
            wait_until("restoration to wait", kernel::restoring).map_err(|e| e.to_string())?;
            gate.release().map_err(|e| e.to_string())
        });
        let events = probe.finish()?;
        releaser.join().expect("releaser")?;
        Ok((events, foreign.join().expect("foreign open")?))
    })?;

    assert!(fd >= 0 && errno == 0, "fd {fd}, errno {errno}");
    let metadata = std::fs::metadata(&gate.path)?;
    let identity = (metadata.dev(), metadata.ino());
    let seen: Vec<_> = events
        .opens
        .iter()
        .filter(|event| event.identity == identity)
        .collect();
    assert_eq!(seen.len(), 1, "{events:?}");
    assert!(seen[0].foreign && seen[0].fd == fd && seen[0].access == kernel::O_RDONLY);
    // SAFETY: `fd` was just returned by the open above and is closed exactly once.
    drop(unsafe { OwnedFd::from_raw_fd(fd) });
    assert_eq!(kernel::SyscallProbe::table()?, saved);
    assert_eq!(kernel::callbacks_in_flight(), 0);
    Ok(())
}

/// A callback that cannot finish within the quiescence bound fails the restoration loudly (the
/// entries are restored all the same), and its late event never enters a probe started afterwards.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn a_callback_that_outlives_restoration_fails_it_and_never_enters_the_next_probe() -> TestResult {
    use std::os::fd::{FromRawFd, OwnedFd};

    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let gate = Gate::new(directory.path())?;
    let path = std::ffi::CString::new(gate.path.to_str().ok_or("path")?)?;
    kernel::initialize_production_hooks()?;
    let saved = kernel::SyscallProbe::table()?;
    let probe = kernel::SyscallProbe::start()?;
    probe.set_quiescence(std::time::Duration::from_millis(100));

    let next_events = std::thread::scope(|scope| -> TestResult<_> {
        let _unblock = Unblock(&gate);
        let foreign = scope.spawn(|| kernel::call_open(&path, kernel::O_RDONLY, 0));
        wait_until("the foreign open to be running", || {
            kernel::callbacks_in_flight() == 1
        })?;
        let error = probe
            .finish()
            .expect_err("restoration finished while a callback was still running");
        assert!(error.contains("still running"), "{error}");
        assert_eq!(
            kernel::SyscallProbe::table()?,
            saved,
            "restored all the same"
        );

        // A new probe is armed while the old callback is still inside the kernel; it ends now.
        let next = kernel::SyscallProbe::start()?;
        gate.release()?;
        let (fd, errno) = foreign.join().expect("foreign open")?;
        assert!(fd >= 0 && errno == 0, "fd {fd}, errno {errno}");
        // SAFETY: `fd` was just returned by the open above and is closed exactly once.
        drop(unsafe { OwnedFd::from_raw_fd(fd) });
        Ok(next.finish()?)
    })?;
    assert!(
        next_events.opens.is_empty() && next_events.failed_opens == 0,
        "the old callback's event entered the next probe: {next_events:?}"
    );
    assert_eq!(kernel::SyscallProbe::table()?, saved);
    Ok(())
}

/// The native entries a participating caller can fetch from the syscall table.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug)]
enum Entry {
    Open,
    Mmap,
    Fstat,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl Entry {
    /// What the call returns and leaves in `errno`, exactly as the kernel gives it: a refused
    /// open of an absent path, an anonymous map that succeeds (`1` would be a failed one), and an
    /// `fstat` of descriptor -1.
    fn expected(self) -> (i64, std::ffi::c_int) {
        match self {
            Entry::Open => (-1, 2),
            Entry::Mmap => (0, 0),
            Entry::Fstat => (-1, 9),
        }
    }

    /// Whether each receipt the probe kept for this entry was made by a foreign thread.
    fn receipts(self, events: &kernel::Events) -> Vec<bool> {
        match self {
            Entry::Open => events.open_failures.iter().map(|f| f.foreign).collect(),
            Entry::Mmap => events.maps.iter().map(|map| map.foreign).collect(),
            Entry::Fstat => events.fstat_failures.iter().map(|f| f.foreign).collect(),
        }
    }

    /// Fetches the entry from the table, tells the test, waits to be resumed, and only then
    /// calls what it fetched.
    fn fetch_pause_call(
        self,
        absent: &std::ffi::CStr,
        paused: &std::sync::mpsc::Sender<()>,
        resume: &std::sync::mpsc::Receiver<()>,
    ) -> Result<(i64, std::ffi::c_int), String> {
        const MAP_PRIVATE: std::ffi::c_int = 2;
        const MAP_ANON: std::ffi::c_int = 0x1000;
        let pause = || {
            let _ = paused.send(());
            let _ = resume.recv_timeout(std::time::Duration::from_secs(60));
        };
        match self {
            Entry::Open => {
                let fetched = kernel::fetch_open()?;
                pause();
                let (fd, errno) = fetched.invoke(absent, 0, 0);
                Ok((i64::from(fd), errno))
            }
            Entry::Mmap => {
                let fetched = kernel::fetch_mmap()?;
                pause();
                let (address, errno) =
                    fetched.invoke(4096, kernel::PROT_READ, MAP_PRIVATE | MAP_ANON, -1, 0);
                if address != usize::MAX {
                    kernel::unmap(address as *mut _, 4096)
                        .map_err(|errno| format!("munmap: errno {errno}"))?;
                }
                Ok((i64::from(address == usize::MAX), errno))
            }
            Entry::Fstat => {
                let fetched = kernel::fetch_fstat()?;
                pause();
                let (result, errno) = fetched.invoke(-1);
                Ok((i64::from(result), errno))
            }
        }
    }
}

/// A participating native caller owns its observation from before it reads the entry from the
/// table, not from when the callback starts. A caller paused between the fetch and the call is
/// either waited for (its event is kept, attributed to the foreign thread, with the kernel's exact
/// result and `errno`), or restoration fails loudly within its bound; its late call is then
/// forwarded unobserved and never recorded into a probe armed after the one it fetched under.
/// Nothing is locked while the caller is paused or while restoration waits.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn a_caller_paused_between_fetching_an_entry_and_calling_it_is_drained_or_fails_the_proof()
-> TestResult {
    use std::sync::mpsc::channel;
    use std::time::Duration;

    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let absent = std::ffi::CString::new(directory.path().join("absent").to_str().ok_or("path")?)?;
    let absent = &absent;
    kernel::initialize_production_hooks()?;
    let saved = kernel::SyscallProbe::table()?;
    let settled = |entry: Entry| -> TestResult {
        assert_eq!(kernel::SyscallProbe::table()?, saved, "{entry:?}");
        assert!(!kernel::armed(), "{entry:?}");
        assert_eq!(
            (
                kernel::acquisitions_pending(),
                kernel::callbacks_in_flight()
            ),
            (0, 0),
            "{entry:?}"
        );
        Ok(())
    };

    // A fetch that is never followed by its call gives its registration back.
    let probe = kernel::SyscallProbe::start()?;
    let fetched = kernel::fetch_open()?;
    assert_eq!(kernel::acquisitions_pending(), 1);
    drop(fetched);
    assert_eq!(kernel::acquisitions_pending(), 0);
    probe.finish()?;
    assert_eq!(kernel::SyscallProbe::table()?, saved);

    for entry in [Entry::Open, Entry::Mmap, Entry::Fstat] {
        let expected = entry.expected();

        // Drained: restoration waits for the paused caller, which is resumed once restoration is
        // waiting (or, were it not, once the probe is gone).
        let probe = kernel::SyscallProbe::start()?;
        probe.set_quiescence(Duration::from_secs(60));
        let (paused_tx, paused_rx) = channel();
        let (resume_tx, resume_rx) = channel();
        let (finished, call, at_pause) = std::thread::scope(|scope| -> TestResult<_> {
            let caller =
                scope.spawn(move || entry.fetch_pause_call(absent, &paused_tx, &resume_rx));
            paused_rx.recv_timeout(Duration::from_secs(30))?;
            let at_pause = (
                kernel::acquisitions_pending(),
                kernel::callbacks_in_flight(),
            );
            let releaser = scope.spawn(move || -> Result<(), String> {
                wait_until("restoration to begin or end", || {
                    kernel::restoring() || !kernel::armed()
                })
                .map_err(|error| error.to_string())?;
                resume_tx.send(()).map_err(|error| error.to_string())
            });
            let finished = probe.finish();
            releaser.join().expect("releaser")?;
            Ok((finished, caller.join().expect("caller"), at_pause))
        })?;
        let events = finished.map_err(|error| format!("{entry:?}: {error}"))?;
        assert_eq!(call?, expected, "{entry:?}");
        assert_eq!(entry.receipts(&events), [true], "{entry:?}: {events:?}");
        assert_eq!(at_pause, (1, 0), "{entry:?}: registered, not yet running");
        settled(entry)?;

        // Not drained in time, then not rearmed or rearmed before the caller resumes.
        for rearm in [false, true] {
            let probe = kernel::SyscallProbe::start()?;
            probe.set_quiescence(Duration::from_millis(100));
            let (paused_tx, paused_rx) = channel();
            let (resume_tx, resume_rx) = channel();
            let (finished, table, next, call) = std::thread::scope(|scope| -> TestResult<_> {
                let caller =
                    scope.spawn(move || entry.fetch_pause_call(absent, &paused_tx, &resume_rx));
                paused_rx.recv_timeout(Duration::from_secs(30))?;
                let finished = probe.finish();
                let table = kernel::SyscallProbe::table()?;
                let next = if rearm {
                    Some(kernel::SyscallProbe::start()?)
                } else {
                    None
                };
                resume_tx.send(())?;
                Ok((finished, table, next, caller.join().expect("caller")))
            })?;
            let error =
                finished.expect_err("restoration finished with a caller paused after its fetch");
            assert!(
                error.contains("fetched a probe entry"),
                "{entry:?}: {error}"
            );
            assert_eq!(table, saved, "{entry:?}: restored all the same");
            assert_eq!(call?, expected, "{entry:?} rearm={rearm}");
            if let Some(next) = next {
                let events = next.finish()?;
                assert!(
                    events.opens.is_empty()
                        && events.maps.is_empty()
                        && events.fstat_failures.is_empty()
                        && events.open_failures.is_empty()
                        && events.failed_opens == 0,
                    "{entry:?}: the call fetched under the old probe entered the new one: {events:?}"
                );
            }
            settled(entry)?;
        }
    }
    Ok(())
}

/// The edge of that coverage, as a test so that the documentation stays true: an entry fetched
/// without registering (as SQLite's own unix VFS and any direct `xGetSystemCall` caller do) is not
/// waited for. Restoration finishes at once and successfully while such a caller is paused, the
/// call is forwarded with the kernel's exact result and `errno` and is not in that probe's events;
/// invoked while another probe is armed it is attributed to that probe, like any call made
/// through the table then.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn an_entry_fetched_without_registering_is_outside_the_probes_coverage() -> TestResult {
    use std::sync::mpsc::channel;
    use std::time::Duration;

    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let absent = std::ffi::CString::new(directory.path().join("absent").to_str().ok_or("path")?)?;
    let absent = &absent;
    kernel::initialize_production_hooks()?;
    let saved = kernel::SyscallProbe::table()?;
    let fetch_and_call = move |paused: std::sync::mpsc::Sender<()>,
                               resume: std::sync::mpsc::Receiver<()>|
          -> Result<(i64, i32), String> {
        // SAFETY: the name is NUL-terminated; the unix VFS is registered with a system-call
        // table, and its `open` entry has the documented C signature.
        let open = unsafe {
            let vfs = rusqlite::ffi::sqlite3_vfs_find(c"unix".as_ptr());
            let get = (*vfs).xGetSystemCall.ok_or("xGetSystemCall")?;
            let call = get(vfs, c"open".as_ptr()).ok_or("open entry")?;
            std::mem::transmute::<unsafe extern "C" fn(), kernel::OpenFn>(call)
        };
        let _ = paused.send(());
        let _ = resume.recv_timeout(Duration::from_secs(60));
        // SAFETY: the path is valid for the call.
        let fd = unsafe { open(absent.as_ptr(), kernel::O_RDONLY, 0) };
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        Ok((i64::from(fd), errno))
    };

    for rearm in [false, true] {
        let probe = kernel::SyscallProbe::start()?;
        probe.set_quiescence(Duration::from_secs(60));
        let (paused_tx, paused_rx) = channel();
        let (resume_tx, resume_rx) = channel();
        let (finished, next, call) = std::thread::scope(|scope| -> TestResult<_> {
            let caller = scope.spawn(move || fetch_and_call(paused_tx, resume_rx));
            paused_rx.recv_timeout(Duration::from_secs(30))?;
            let finished = probe.finish();
            let next = if rearm {
                Some(kernel::SyscallProbe::start()?)
            } else {
                None
            };
            resume_tx.send(())?;
            Ok((finished, next, caller.join().expect("caller")))
        })?;
        let events = finished?;
        assert!(
            events.open_failures.is_empty() && events.failed_opens == 0,
            "{events:?}"
        );
        assert_eq!(call?, (-1, 2), "rearm={rearm}");
        if let Some(next) = next {
            let events = next.finish()?;
            assert_eq!(
                events.open_failures.len(),
                1,
                "an unregistered call is attributed to the probe armed when it runs: {events:?}"
            );
        }
        assert_eq!(kernel::SyscallProbe::table()?, saved);
    }
    Ok(())
}

/// `(fd, errno, foreign)` of each failing `fstat` the probe kept, in order.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn fstat_receipts(events: &kernel::Events) -> Vec<(std::ffi::c_int, std::ffi::c_int, bool)> {
    events
        .fstat_failures
        .iter()
        .map(|failure| (failure.fd, failure.errno, failure.foreign))
        .collect()
}

/// What the handles of one thread do, in order, in the ownership controls below.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug)]
enum Step {
    InvokeA,
    InvokeB,
    DropA,
    DropB,
}

/// Handles fetched by one thread are independent. Each owns its generation and its pending
/// registration, so dropping or invoking one in any order releases exactly its own registration
/// and leaves the other pending; the callback of an invocation sees only the handle being invoked,
/// so a plain call made through the table while a handle is held does not consume that handle's
/// registration; and every invoked handle leaves exactly its own receipt, made by the owner
/// thread, with the kernel's `errno`. No registration is left behind: restoration within a short
/// bound succeeds.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn overlapping_fetched_handles_on_one_thread_own_their_registrations_and_receipts() -> TestResult {
    use std::time::Duration;

    const EBADF: std::ffi::c_int = 9;
    let _guard = vfs_test_guard();
    kernel::initialize_production_hooks()?;
    let saved = kernel::SyscallProbe::table()?;

    use Step::{DropA, DropB, InvokeA, InvokeB};
    for steps in [
        [DropA, InvokeB],
        [DropB, InvokeA],
        [InvokeA, InvokeB],
        [InvokeB, InvokeA],
        [InvokeA, DropB],
        [InvokeB, DropA],
        [DropA, DropB],
        [DropB, DropA],
    ] {
        let probe = kernel::SyscallProbe::start()?;
        probe.set_quiescence(Duration::from_millis(100));
        let mut a = Some(kernel::fetch_fstat()?);
        let mut b = Some(kernel::fetch_fstat()?);
        assert_eq!(kernel::acquisitions_pending(), 2, "{steps:?}");
        let mut expected = Vec::new();
        for step in steps {
            match step {
                InvokeA => {
                    let handle = a.take().ok_or("A was consumed")?;
                    assert_eq!(handle.invoke(-1), (-1, EBADF), "{steps:?}");
                    expected.push((-1, EBADF, false));
                }
                InvokeB => {
                    let handle = b.take().ok_or("B was consumed")?;
                    assert_eq!(handle.invoke(-2), (-1, EBADF), "{steps:?}");
                    expected.push((-2, EBADF, false));
                }
                DropA => drop(a.take().ok_or("A was consumed")?),
                DropB => drop(b.take().ok_or("B was consumed")?),
            }
            let held = usize::from(a.is_some()) + usize::from(b.is_some());
            assert_eq!(
                (
                    kernel::acquisitions_pending(),
                    kernel::callbacks_in_flight()
                ),
                (held, 0),
                "{steps:?} after {step:?}"
            );
            assert_eq!(
                fstat_receipts(&probe.events()),
                expected,
                "{steps:?} after {step:?}"
            );
        }
        let events = probe
            .finish()
            .map_err(|error| format!("{steps:?}: {error}"))?;
        assert_eq!(fstat_receipts(&events), expected, "{steps:?}");
        assert_eq!(kernel::SyscallProbe::table()?, saved, "{steps:?}");
        assert!(!kernel::armed(), "{steps:?}");
    }

    // A call made through the table while a handle is held is not an invocation of that handle.
    let probe = kernel::SyscallProbe::start()?;
    probe.set_quiescence(Duration::from_millis(100));
    let held = kernel::fetch_fstat()?;
    // SAFETY: the name is NUL-terminated; the unix VFS is registered with a system-call table
    // whose `fstat` entry has the documented C signature.
    let direct = unsafe {
        let vfs = rusqlite::ffi::sqlite3_vfs_find(c"unix".as_ptr());
        let get = (*vfs).xGetSystemCall.ok_or("xGetSystemCall")?;
        let call = get(vfs, c"fstat".as_ptr()).ok_or("fstat entry")?;
        std::mem::transmute::<unsafe extern "C" fn(), kernel::FstatFn>(call)
    };
    let mut buffer = [0_u64; 32];
    // SAFETY: the buffer is larger than `struct stat` and aligned; a bad descriptor only fails.
    let result = unsafe { direct(-3, buffer.as_mut_ptr().cast()) };
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    assert_eq!((result, errno), (-1, EBADF));
    assert_eq!(
        kernel::acquisitions_pending(),
        1,
        "a plain call consumed the registration of a handle it did not invoke"
    );
    assert_eq!(held.invoke(-4), (-1, EBADF));
    assert_eq!(kernel::acquisitions_pending(), 0);
    let events = probe.finish()?;
    assert_eq!(
        fstat_receipts(&events),
        [(-3, EBADF, false), (-4, EBADF, false)]
    );
    assert_eq!(kernel::SyscallProbe::table()?, saved);
    Ok(())
}

/// A handle fetched under a probe that has ended stays that probe's, whatever else the thread
/// fetches or drops afterwards: with a later probe armed and its own handle held, dropping or
/// invoking the old one releases and records nothing of the later one (its registration and its
/// receipts are exact); and a handle fetched while no probe was armed does not replace the
/// old one's ownership, so its call is never attributed to the probe armed after it.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn a_stale_fetched_handle_never_touches_a_later_probes_registrations() -> TestResult {
    use std::time::Duration;

    const EBADF: std::ffi::c_int = 9;
    let _guard = vfs_test_guard();
    kernel::initialize_production_hooks()?;
    let saved = kernel::SyscallProbe::table()?;

    // Old A, new B (armed after A's probe ended), in every order of dropping and invoking.
    use Step::{DropA, DropB, InvokeA, InvokeB};
    for steps in [
        [DropA, InvokeB],
        [DropB, DropA],
        [InvokeA, InvokeB],
        [InvokeB, InvokeA],
    ] {
        let old = kernel::SyscallProbe::start()?;
        old.set_quiescence(Duration::from_millis(100));
        let mut a = Some(kernel::fetch_fstat()?);
        let error = old
            .finish()
            .expect_err("restoration finished with a handle that was fetched and never invoked");
        assert!(
            error.contains("fetched a probe entry"),
            "{steps:?}: {error}"
        );
        assert_eq!(kernel::SyscallProbe::table()?, saved, "{steps:?}");

        let next = kernel::SyscallProbe::start()?;
        next.set_quiescence(Duration::from_millis(100));
        let mut b = Some(kernel::fetch_fstat()?);
        assert_eq!(kernel::acquisitions_pending(), 1, "{steps:?}: B only");
        let mut expected = Vec::new();
        for step in steps {
            match step {
                InvokeA => {
                    let handle = a.take().ok_or("A was consumed")?;
                    assert_eq!(handle.invoke(-1), (-1, EBADF), "{steps:?}");
                }
                InvokeB => {
                    let handle = b.take().ok_or("B was consumed")?;
                    assert_eq!(handle.invoke(-2), (-1, EBADF), "{steps:?}");
                    expected.push((-2, EBADF, false));
                }
                DropA => drop(a.take().ok_or("A was consumed")?),
                DropB => drop(b.take().ok_or("B was consumed")?),
            }
            assert_eq!(
                (
                    kernel::acquisitions_pending(),
                    kernel::callbacks_in_flight()
                ),
                (usize::from(b.is_some()), 0),
                "{steps:?} after {step:?}: only B's registration may remain"
            );
            assert_eq!(
                fstat_receipts(&next.events()),
                expected,
                "{steps:?} after {step:?}: the old handle entered the later probe"
            );
        }
        let events = next
            .finish()
            .map_err(|error| format!("{steps:?}: {error}"))?;
        assert_eq!(fstat_receipts(&events), expected, "{steps:?}");
        assert_eq!(kernel::SyscallProbe::table()?, saved, "{steps:?}");
    }

    // Old A, and a helper fetched and used while no probe is armed, before the next one is.
    for invoke_helper in [false, true] {
        let old = kernel::SyscallProbe::start()?;
        old.set_quiescence(Duration::from_millis(100));
        let a = kernel::fetch_fstat()?;
        old.finish()
            .expect_err("restoration finished with a handle that was fetched and never invoked");
        assert!(!kernel::armed());
        let helper = kernel::fetch_fstat()?;
        assert_eq!(kernel::acquisitions_pending(), 0, "no probe is armed");
        if invoke_helper {
            assert_eq!(helper.invoke(-5), (-1, EBADF), "no probe: forwarded");
        } else {
            drop(helper);
        }
        let next = kernel::SyscallProbe::start()?;
        next.set_quiescence(Duration::from_millis(100));
        assert_eq!(a.invoke(-1), (-1, EBADF), "invoke_helper={invoke_helper}");
        let events = next.finish()?;
        assert!(
            events.fstat_failures.is_empty() && events.errors.is_empty(),
            "invoke_helper={invoke_helper}: the call fetched under the old probe entered the next \
             one: {events:?}"
        );
        assert_eq!(kernel::acquisitions_pending(), 0);
        assert_eq!(kernel::SyscallProbe::table()?, saved);
    }
    Ok(())
}

/// Fetches `entry` with `before_read` run after its registration and before the table read, then
/// calls what it fetched exactly as [`Entry::fetch_pause_call`] does.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn fetch_registered_then_call(
    entry: Entry,
    absent: &std::ffi::CStr,
    before_read: impl FnOnce(),
) -> Result<(i64, std::ffi::c_int), String> {
    const MAP_PRIVATE: std::ffi::c_int = 2;
    const MAP_ANON: std::ffi::c_int = 0x1000;
    match entry {
        Entry::Open => {
            let (fd, errno) = kernel::fetch_open_between(before_read)?.invoke(absent, 0, 0);
            Ok((i64::from(fd), errno))
        }
        Entry::Mmap => {
            let fetched = kernel::fetch_mmap_between(before_read)?;
            let (address, errno) =
                fetched.invoke(4096, kernel::PROT_READ, MAP_PRIVATE | MAP_ANON, -1, 0);
            if address != usize::MAX {
                kernel::unmap(address as *mut _, 4096)
                    .map_err(|errno| format!("munmap: errno {errno}"))?;
            }
            Ok((i64::from(address == usize::MAX), errno))
        }
        Entry::Fstat => {
            let (result, errno) = kernel::fetch_fstat_between(before_read)?.invoke(-1);
            Ok((i64::from(result), errno))
        }
    }
}

/// A caller that has registered with the armed probe but not yet read the table when restoration
/// puts the entries back would read the restored entry, and its call would run outside the
/// observation. The pause is between the registration and the table read, and restoration is
/// resumed only once it has put the entries back: the fetch is refused, the observation fails
/// explicitly (the caller's receipt cannot exist), and the finish is never a clean one that is
/// missing a participating operation. With the probe still armed the same pause changes nothing:
/// the call is observed.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn a_fetch_registered_before_the_table_read_never_finishes_clean_after_restoration() -> TestResult {
    use std::sync::mpsc::channel;
    use std::time::Duration;

    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let absent = std::ffi::CString::new(directory.path().join("absent").to_str().ok_or("path")?)?;
    let absent = &absent;
    kernel::initialize_production_hooks()?;
    let saved = kernel::SyscallProbe::table()?;
    let settled = |entry: Entry| -> TestResult {
        assert_eq!(kernel::SyscallProbe::table()?, saved, "{entry:?}");
        assert!(!kernel::armed(), "{entry:?}");
        assert_eq!(
            (
                kernel::acquisitions_pending(),
                kernel::callbacks_in_flight()
            ),
            (0, 0),
            "{entry:?}"
        );
        Ok(())
    };

    for entry in [Entry::Open, Entry::Mmap, Entry::Fstat] {
        // Control: resumed with the probe armed, the registered call is observed.
        let probe = kernel::SyscallProbe::start()?;
        probe.set_quiescence(Duration::from_secs(60));
        let (paused_tx, paused_rx) = channel();
        let (resume_tx, resume_rx) = channel();
        let call = std::thread::scope(|scope| -> TestResult<_> {
            let caller = scope.spawn(move || {
                fetch_registered_then_call(entry, absent, || {
                    let _ = paused_tx.send(());
                    let _ = resume_rx.recv_timeout(Duration::from_secs(60));
                })
            });
            paused_rx.recv_timeout(Duration::from_secs(30))?;
            assert_eq!(
                (
                    kernel::acquisitions_pending(),
                    kernel::callbacks_in_flight()
                ),
                (1, 0),
                "{entry:?}: registered, table not yet read"
            );
            resume_tx.send(())?;
            Ok(caller.join().expect("caller"))
        })?;
        assert_eq!(call?, entry.expected(), "{entry:?}");
        let events = probe.finish()?;
        assert_eq!(entry.receipts(&events), [true], "{entry:?}: {events:?}");
        settled(entry)?;

        // Restoration puts the entries back while the caller is between its registration and its
        // table read.
        let probe = kernel::SyscallProbe::start()?;
        probe.set_quiescence(Duration::from_secs(60));
        let (paused_tx, paused_rx) = channel();
        let (resume_tx, resume_rx) = channel();
        let (finished, call) = std::thread::scope(|scope| -> TestResult<_> {
            let caller = scope.spawn(move || {
                fetch_registered_then_call(entry, absent, || {
                    let _ = paused_tx.send(());
                    let _ = resume_rx.recv_timeout(Duration::from_secs(60));
                })
            });
            paused_rx.recv_timeout(Duration::from_secs(30))?;
            let releaser = scope.spawn(move || -> Result<(), String> {
                wait_until("restoration to put the entries back", kernel::restoring)
                    .map_err(|error| error.to_string())?;
                resume_tx.send(()).map_err(|error| error.to_string())
            });
            let finished = probe.finish();
            releaser.join().expect("releaser")?;
            Ok((finished, caller.join().expect("caller")))
        })?;
        let refusal = call.expect_err("the fetch read a restored entry and was not refused");
        assert!(
            refusal.contains("was restored before the registered fetch read it"),
            "{entry:?}: {refusal}"
        );
        let failure = finished.expect_err("the observation finished clean without the call");
        assert!(
            failure.contains("was restored before a registered fetch read it"),
            "{entry:?}: {failure}"
        );
        settled(entry)?;
    }
    Ok(())
}

/// The registrations a probe accounts for are bounded: [`kernel::MAX_ACQUISITIONS`] pending fetches
/// are admitted and one more is refused, nothing registered by the refusal, and the refusal is a
/// sticky failure of the observation even after the count has come back down. A handle that is
/// still held when its thread unwinds is checked in the two real destruction orders, with the
/// setup outside the caught region and the panic required by its private marker: dropped before
/// the probe (the probe outliving the unwind outside it, the registration back while the
/// generation is still armed, `finish` clean with its exact receipt) and after it (the probe's
/// restoration failing within its bound with the handle still held, kept in a state of its own).
/// Either way the exact entries are restored, a fresh probe arms cleanly, and nothing the old
/// probe saw reaches it.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn acquisitions_are_bounded_and_an_unwinding_handle_releases_its_registration() -> TestResult {
    use std::time::Duration;

    const EBADF: std::ffi::c_int = 9;
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let absent = std::ffi::CString::new(directory.path().join("absent").to_str().ok_or("path")?)?;
    kernel::initialize_production_hooks()?;
    let saved = kernel::SyscallProbe::table()?;
    let max = kernel::MAX_ACQUISITIONS;

    let probe = kernel::SyscallProbe::start()?;
    probe.set_quiescence(Duration::from_millis(100));
    let mut held = Vec::new();
    for _ in 0..max {
        held.push(kernel::fetch_fstat()?);
    }
    assert_eq!(kernel::acquisitions_pending(), max);
    let Err(refusal) = kernel::fetch_fstat() else {
        return Err("a fetch beyond the acquisition limit was admitted".into());
    };
    assert!(refusal.contains("refused"), "{refusal}");
    assert_eq!(
        kernel::acquisitions_pending(),
        max,
        "the refusal registered"
    );
    assert_eq!(probe.events().acquisitions_refused, 1);
    // Invoking one makes room; the next fetch is admitted again.
    let first = held.pop().ok_or("held")?;
    assert_eq!(first.invoke(-1), (-1, EBADF));
    assert_eq!(kernel::acquisitions_pending(), max - 1);
    held.push(kernel::fetch_fstat()?);
    assert_eq!(kernel::acquisitions_pending(), max);
    drop(held);
    assert_eq!(kernel::acquisitions_pending(), 0);
    let failure = probe
        .finish()
        .expect_err("a refused fetch left the observation clean");
    assert!(
        failure.contains("1 participating fetch(es) refused at the acquisition limit"),
        "{failure}"
    );
    assert_eq!(kernel::SyscallProbe::table()?, saved);
    assert!(!kernel::armed());

    // Unwinding with a really held fetch, in the two destruction orders. The probe, its completed
    // call and the held handle are set up and checked outside the caught region, so no setup or
    // assertion failure can be taken for the unwind; the deliberate panic carries a marker of a
    // type private to this test, and its payload is required by value.
    #[derive(Debug, Eq, PartialEq)]
    struct Unwind(&'static str);
    // Fields drop in declaration order: the probe, then the handle it was fetched under.
    struct ProbeFirst {
        _probe: kernel::SyscallProbe,
        _handle: kernel::Fetched<kernel::OpenFn>,
    }
    for probe_first in [false, true] {
        let order = if probe_first {
            "probe first"
        } else {
            "handle first"
        };
        drop(kernel::take_discarded_restoration());
        let probe = kernel::SyscallProbe::start()?;
        probe.set_quiescence(Duration::from_millis(100));
        // A completed call of this probe: its receipt is kept while the probe lives.
        let (fd, errno) = kernel::fetch_open()?.invoke(&absent, kernel::O_RDONLY, 0);
        assert_eq!((fd, errno), (-1, 2), "{order}");
        let handle = kernel::fetch_open()?;
        assert_eq!(kernel::acquisitions_pending(), 1, "{order}");

        let payload_of = |unwound: std::thread::Result<()>| -> TestResult<Unwind> {
            let payload = unwound
                .err()
                .ok_or("the closure returned instead of unwinding")?;
            payload
                .downcast::<Unwind>()
                .map(|marker| *marker)
                .map_err(|_| "some other panic was taken for the unwind".into())
        };
        if probe_first {
            // The probe is dropped first: its restoration finds the handle still holding its
            // registration and fails within the bound; `Drop` can only keep that failure. The
            // handle is released afterwards, to a generation that no longer exists.
            let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _held = ProbeFirst {
                    _probe: probe,
                    _handle: handle,
                };
                std::panic::panic_any(Unwind("probe first"));
            }));
            assert_eq!(payload_of(unwound)?, Unwind("probe first"));
            let discarded = kernel::take_discarded_restoration()
                .ok_or("the probe's restoration did not fail with the handle still held")?;
            assert!(
                discarded.contains("fetched a probe entry before restoration"),
                "{discarded}"
            );
            assert!(!kernel::armed());
        } else {
            // Only the handle is lost to the unwind. The probe outlives it, outside: the
            // handle's registration is back while the generation is still armed, and the probe
            // finishes cleanly with the completed call's receipt and nothing else.
            let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _held = handle;
                std::panic::panic_any(Unwind("handle first"));
            }));
            assert_eq!(payload_of(unwound)?, Unwind("handle first"));
            assert!(kernel::armed() && !kernel::restoring());
            assert_eq!(
                (
                    kernel::acquisitions_pending(),
                    kernel::callbacks_in_flight()
                ),
                (0, 0),
                "the unwound handle kept its registration"
            );
            let events = probe.finish()?;
            assert_eq!(events.failed_opens, 1, "{events:?}");
            assert!(
                matches!(
                    events.open_failures[..],
                    [kernel::OpenFailure {
                        errno: 2,
                        foreign: false
                    }]
                ) && events.opens.is_empty(),
                "{events:?}"
            );
            assert!(
                kernel::take_discarded_restoration().is_none(),
                "a restoration that had nothing to wait for failed"
            );
        }
        assert_eq!(kernel::SyscallProbe::table()?, saved, "{order}");
        assert!(!kernel::armed(), "{order}");
        assert_eq!(
            (
                kernel::acquisitions_pending(),
                kernel::callbacks_in_flight()
            ),
            (0, 0),
            "{order}"
        );

        // A fresh probe arms cleanly and holds only its own receipt.
        let fresh = kernel::SyscallProbe::start()?;
        fresh.set_quiescence(Duration::from_millis(100));
        assert_eq!(kernel::fetch_fstat()?.invoke(-1), (-1, EBADF));
        let events = fresh.finish()?;
        assert!(
            events.open_failures.is_empty() && events.failed_opens == 0,
            "{order}: an old receipt reached the fresh probe: {events:?}"
        );
        assert_eq!(fstat_receipts(&events), [(-1, EBADF, false)], "{order}");
        assert_eq!(kernel::SyscallProbe::table()?, saved);
    }
    Ok(())
}

/// The gate sections of a table-access log, each the reads and writes made inside one hold of
/// the gate, in order; an error when holds overlap or an access happened outside one.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn gate_sections(log: &[kernel::TableEvent]) -> Result<Vec<Vec<kernel::TableEvent>>, String> {
    use kernel::TableEvent::{Entered, Left};
    let mut sections = Vec::new();
    let mut open: Option<Vec<kernel::TableEvent>> = None;
    for &event in log {
        match (event, open.as_mut()) {
            (Entered, None) => open = Some(Vec::new()),
            (Left, Some(_)) => sections.push(open.take().unwrap_or_default()),
            (Entered | Left, _) => return Err(format!("overlapping or unbalanced holds: {log:?}")),
            (access, Some(section)) => section.push(access),
            (_, None) => return Err(format!("an access outside the gate: {log:?}")),
        }
    }
    if open.is_some() {
        return Err(format!("a hold that never ended: {log:?}"));
    }
    Ok(sections)
}

/// The reads of the three entries that `table()` makes.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn table_reads(table: [usize; 3]) -> Vec<kernel::TableEvent> {
    (0..3)
        .map(|entry| kernel::TableEvent::Read {
            entry,
            address: table[entry],
        })
        .collect()
}

/// What a restoration (or an installation) of `table` does inside its one hold: each entry set
/// and read back, the last installed first when `restoring`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn table_writes(table: [usize; 3], restoring: bool) -> Vec<kernel::TableEvent> {
    let mut order = [0, 1, 2];
    if restoring {
        order.reverse();
    }
    order
        .into_iter()
        .flat_map(|entry| {
            [
                kernel::TableEvent::Wrote {
                    entry,
                    address: table[entry],
                    code: 0,
                },
                kernel::TableEvent::Read {
                    entry,
                    address: table[entry],
                },
            ]
        })
        .collect()
}

/// Every access to the syscall table, by the participating fetch, the installation, the
/// restoration and `table()`, passes one gate; no timing is involved. A test holds the gate and
/// starts the participant: it is counted as waiting at the gate (`contentions`, `waiting`) and has
/// made no access (the table still reads as before, through the holder, and the order witness
/// holds only the holder's own section) until the gate is released. The participant is never run
/// against a raw access: with the gate missing it finishes without waiting, and the test fails on
/// that before any conflicting access is made. The gate sections of the order witness are then
/// exactly the accesses in sequence: one hold for the saves, one for the installation with every
/// read-back, one for the restoration with every read-back, one per fetch. A real fetch and a real
/// restoration contending for the gate end in one of its two serial orders: the fetch gets the
/// installed entry and is observed, or it gets the restored one and is refused, failing the
/// observation; never a clean finish without its call.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn the_table_gate_serializes_participating_reads_installation_and_restoration() -> TestResult {
    use kernel::TableEvent::Read;
    use std::sync::mpsc::channel;
    use std::time::Duration;

    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let absent = std::ffi::CString::new(directory.path().join("absent").to_str().ok_or("path")?)?;
    let absent = &absent;
    kernel::initialize_production_hooks()?;
    let saved = kernel::SyscallProbe::table()?;
    let settled = |what: &str| -> TestResult {
        assert_eq!(kernel::SyscallProbe::table()?, saved, "{what}");
        assert!(!kernel::armed(), "{what}");
        assert_eq!(
            (
                kernel::acquisitions_pending(),
                kernel::callbacks_in_flight()
            ),
            (0, 0),
            "{what}"
        );
        Ok(())
    };
    // Waits until `count` more threads wait at the gate, or `done` says the one under test got
    // through it; the latter is the failure.
    let blocked = |what: &str, base: u64, count: u64, done: &dyn Fn() -> bool| -> TestResult {
        wait_until(what, || {
            kernel::table_contentions() >= base + count || done()
        })?;
        assert!(
            !done() && kernel::table_contentions() == base + count,
            "{what}: it went through the held gate"
        );
        assert_eq!(kernel::table_waiting(), count as usize, "{what}");
        Ok(())
    };
    // A probe armed on a thread of its own, which finishes when told to.
    let owned_probe = |armed: std::sync::mpsc::Sender<()>,
                       go: std::sync::mpsc::Receiver<()>|
     -> Result<kernel::Events, String> {
        let probe = kernel::SyscallProbe::start()?;
        probe.set_quiescence(Duration::from_secs(60));
        armed.send(()).map_err(|error| error.to_string())?;
        go.recv_timeout(Duration::from_secs(60))
            .map_err(|error| error.to_string())?;
        probe.finish()
    };

    // A fetch of each entry waits for the gate, after its registration, and reads what is there
    // when it gets it: the installed entry; the restoration then follows.
    for entry in [Entry::Open, Entry::Mmap, Entry::Fstat] {
        let probe = kernel::SyscallProbe::start()?;
        probe.set_quiescence(Duration::from_secs(60));
        let armed = kernel::SyscallProbe::table()?;
        assert_ne!(armed, saved, "{entry:?}");
        kernel::clear_table_log();
        let base = kernel::table_contentions();
        let call = std::thread::scope(|scope| -> TestResult<_> {
            let held = kernel::hold_table();
            let reader = scope.spawn(|| fetch_registered_then_call(entry, absent, || {}));
            blocked("the fetch to wait", base, 1, &|| reader.is_finished())?;
            assert_eq!(
                (
                    kernel::acquisitions_pending(),
                    kernel::callbacks_in_flight()
                ),
                (1, 0),
                "{entry:?}: registered before its table read"
            );
            assert_eq!(
                kernel::table_log()?,
                [kernel::TableEvent::Entered],
                "{entry:?}: the fetch read the table while the gate was held"
            );
            assert_eq!(held.table()?, armed, "{entry:?}");
            drop(held);
            Ok(reader.join().expect("reader"))
        })?;
        assert_eq!(call?, entry.expected(), "{entry:?}");
        let events = probe.finish()?;
        assert_eq!(entry.receipts(&events), [true], "{entry:?}: {events:?}");
        assert_eq!(
            gate_sections(&kernel::table_log()?)?,
            [
                table_reads(armed),
                vec![Read {
                    entry: entry as usize,
                    address: armed[entry as usize]
                }],
                table_writes(saved, true)
            ],
            "{entry:?}"
        );
        settled("a fetch behind the gate")?;
    }

    // `table()` waits for the gate too.
    kernel::clear_table_log();
    let base = kernel::table_contentions();
    let table = std::thread::scope(|scope| -> TestResult<_> {
        let held = kernel::hold_table();
        let reader = scope.spawn(kernel::SyscallProbe::table);
        blocked("table() to wait", base, 1, &|| reader.is_finished())?;
        assert_eq!(held.table()?, saved);
        drop(held);
        Ok(reader.join().expect("reader")?)
    })?;
    assert_eq!(table, saved);
    assert_eq!(
        gate_sections(&kernel::table_log()?)?,
        [table_reads(saved), table_reads(saved)]
    );

    // A restoration waits for the gate and has put nothing back until it gets it.
    let (armed_tx, armed_rx) = channel();
    let (go_tx, go_rx) = channel();
    let (events, armed) = std::thread::scope(|scope| -> TestResult<_> {
        let owner = scope.spawn(move || owned_probe(armed_tx, go_rx));
        armed_rx.recv_timeout(Duration::from_secs(30))?;
        let armed = kernel::SyscallProbe::table()?;
        assert_ne!(armed, saved);
        kernel::clear_table_log();
        let base = kernel::table_contentions();
        let held = kernel::hold_table();
        go_tx.send(())?;
        blocked("the restoration to wait", base, 1, &|| owner.is_finished())?;
        assert!(
            kernel::armed() && !kernel::restoring(),
            "the restoration began behind a held gate"
        );
        assert_eq!(kernel::table_log()?, [kernel::TableEvent::Entered]);
        assert_eq!(held.table()?, armed, "restoration wrote behind a held gate");
        drop(held);
        Ok((owner.join().expect("owner")?, armed))
    })?;
    events.checked()?;
    assert_eq!(
        gate_sections(&kernel::table_log()?)?,
        [table_reads(armed), table_writes(saved, true)]
    );
    settled("a restoration behind the gate")?;

    // An installation waits for the gate, both at its saves and, armed and paused, at its
    // installation, and installs nothing until it gets it.
    for paused in [false, true] {
        let what = if paused { "installation" } else { "saves" };
        let (paused_tx, paused_rx) = channel();
        let (resume_tx, resume_rx) = channel();
        let (started_tx, started_rx) = channel();
        let (finish_tx, finish_rx) = channel();
        // Set by the owner as soon as its start returned: it got through the gate.
        let started = &std::sync::atomic::AtomicBool::new(false);
        let (events, armed, log) = std::thread::scope(|scope| -> TestResult<_> {
            let base = kernel::table_contentions();
            // The saves are contended by taking the gate before the probe can start.
            let early = if paused {
                None
            } else {
                kernel::clear_table_log();
                Some(kernel::hold_table())
            };
            let owner = scope.spawn(move || -> Result<kernel::Events, String> {
                let probe = if paused {
                    kernel::SyscallProbe::start_paused_before_install(|| {
                        let _ = paused_tx.send(());
                        let _ = resume_rx.recv_timeout(Duration::from_secs(60));
                    })?
                } else {
                    kernel::SyscallProbe::start()?
                };
                probe.set_quiescence(Duration::from_secs(60));
                started.store(true, std::sync::atomic::Ordering::SeqCst);
                started_tx.send(()).map_err(|error| error.to_string())?;
                finish_rx
                    .recv_timeout(Duration::from_secs(60))
                    .map_err(|error| error.to_string())?;
                probe.finish()
            });
            let held = if let Some(held) = early {
                held
            } else {
                // Armed, saved, and about to install.
                paused_rx.recv_timeout(Duration::from_secs(30))?;
                kernel::clear_table_log();
                let held = kernel::hold_table();
                resume_tx.send(())?;
                held
            };
            blocked(what, base, 1, &|| {
                owner.is_finished() || started.load(std::sync::atomic::Ordering::SeqCst)
            })?;
            assert_eq!(kernel::armed(), paused, "{what}");
            assert_eq!(held.table()?, saved, "{what}: installed behind a held gate");
            drop(held);
            started_rx.recv_timeout(Duration::from_secs(30))?;
            let log = kernel::table_log()?;
            let armed = kernel::SyscallProbe::table()?;
            assert_ne!(armed, saved, "{what}");
            finish_tx.send(())?;
            Ok((owner.join().expect("owner")?, armed, log))
        })?;
        events.checked()?;
        let mut expected = vec![table_reads(saved)];
        if !paused {
            expected.push(table_reads(saved));
        }
        expected.push(table_writes(armed, false));
        assert_eq!(gate_sections(&log)?, expected, "{what}");
        settled(what)?;
    }

    // A real fetch and a real restoration contending: one serial order or the other.
    let mut orders = [0_usize; 2];
    for round in 0..8 {
        let (armed_tx, armed_rx) = channel();
        let (go_tx, go_rx) = channel();
        let (finished, call, log, armed) = std::thread::scope(|scope| -> TestResult<_> {
            let owner = scope.spawn(move || owned_probe(armed_tx, go_rx));
            armed_rx.recv_timeout(Duration::from_secs(30))?;
            let armed = kernel::SyscallProbe::table()?;
            kernel::clear_table_log();
            let base = kernel::table_contentions();
            let held = kernel::hold_table();
            go_tx.send(())?;
            blocked("the restoration to wait", base, 1, &|| owner.is_finished())?;
            let reader = scope.spawn(|| fetch_registered_then_call(Entry::Open, absent, || {}));
            blocked("the fetch to wait", base, 2, &|| reader.is_finished())?;
            assert_eq!(
                (
                    kernel::acquisitions_pending(),
                    kernel::callbacks_in_flight()
                ),
                (1, 0),
                "round {round}: the fetch registered, the restoration has not begun"
            );
            assert_eq!(held.table()?, armed, "round {round}");
            drop(held);
            let call = reader.join().expect("reader");
            let finished = owner.join().expect("owner");
            Ok((finished, call, kernel::table_log()?, armed))
        })?;
        let sections = gate_sections(&log)?;
        assert_eq!(sections.len(), 3, "round {round}: {log:?}");
        assert_eq!(sections[0], table_reads(armed), "round {round}");
        let fetch_read = |address| vec![Read { entry: 0, address }];
        if sections[1] == fetch_read(armed[0]) {
            // The fetch got the installed entry: observed, and the restoration waited for it.
            orders[0] += 1;
            assert_eq!(sections[2], table_writes(saved, true), "round {round}");
            assert_eq!(call?, Entry::Open.expected(), "round {round}");
            let events = finished?;
            assert_eq!(Entry::Open.receipts(&events), [true], "round {round}");
        } else {
            // The restoration got in first: the fetch reads the restored entry and is refused.
            orders[1] += 1;
            assert_eq!(sections[1], table_writes(saved, true), "round {round}");
            assert_eq!(sections[2], fetch_read(saved[0]), "round {round}");
            let refusal = call.expect_err("the fetch read a restored entry and was not refused");
            assert!(
                refusal.contains("was restored before the registered fetch read it"),
                "round {round}: {refusal}"
            );
            let failure = finished.expect_err("the observation finished clean without the call");
            assert!(
                failure.contains("was restored before a registered fetch read it"),
                "round {round}: {failure}"
            );
        }
        settled("a fetch and a restoration contending")?;
    }
    assert_eq!(orders.iter().sum::<usize>(), 8, "{orders:?}");
    Ok(())
}

/// What a hook run inside an invocation saw and did, kept for the test to check (a hook runs in
/// the middle of a native call, where it cannot assert).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Default, PartialEq)]
struct Nested {
    /// `(pending, in flight)` when the hook started, inside the outer invocation.
    before: Option<(usize, usize)>,
    /// A participating call made from the hook while the outer one runs.
    inner: Option<Result<(std::ffi::c_int, std::ffi::c_int), String>>,
    /// `(pending, in flight)` right after it returned.
    after: Option<(usize, usize)>,
    /// The restoration of the probe was waiting for the outer call.
    restoring: Option<Result<(), String>>,
    /// A plain call of the table, made after the inner one returned.
    plain: Option<(std::ffi::c_int, std::ffi::c_int)>,
}

/// The `fstat` entry as SQLite's unix VFS reads it, without registering.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn plain_fstat_entry() -> Result<kernel::FstatFn, String> {
    // SAFETY: the name is NUL-terminated; the unix VFS is registered with a system-call table
    // whose `fstat` entry has the documented C signature.
    unsafe {
        let vfs = rusqlite::ffi::sqlite3_vfs_find(c"unix".as_ptr());
        if vfs.is_null() {
            return Err("unix VFS unavailable".into());
        }
        let get = (*vfs).xGetSystemCall.ok_or("xGetSystemCall")?;
        let call = get(vfs, c"fstat".as_ptr()).ok_or("fstat entry")?;
        Ok(std::mem::transmute::<unsafe extern "C" fn(), kernel::FstatFn>(call))
    }
}

/// `fstat` of a bad descriptor through `entry`; `(result, errno)`.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn call_plain_fstat(
    entry: kernel::FstatFn,
    fd: std::ffi::c_int,
) -> (std::ffi::c_int, std::ffi::c_int) {
    let mut buffer = [0_u64; 32];
    // SAFETY: the buffer is larger than `struct stat` and aligned; a bad descriptor only fails.
    let result = unsafe { entry(fd, buffer.as_mut_ptr().cast()) };
    (
        result,
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
    )
}

/// A participating call made from inside another one on the same thread: the production open
/// hook runs inside the outer handle's `open`, and the test's open hook calls a second
/// participating `open` from it. The outer handle's fetch belongs to a probe that has ended, the
/// inner one to the probe armed now. The inner call is observed exactly once and settles its own
/// registration; when it returns the outer invocation is the one in progress again, so a plain
/// call of the table made afterwards is still the stale outer's and is forwarded unobserved,
/// instead of being attributed to the probe armed now; and the outer call is not observed.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn a_nested_invocation_restores_the_stale_outer_one_when_it_returns() -> TestResult {
    use quotern_core::ingest::sqlite_ro::{bind_store, set_open_hook};
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::time::Duration;

    const EBADF: std::ffi::c_int = 9;
    const ENOENT: std::ffi::c_int = 2;
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let path = |name: &str| -> TestResult<std::ffi::CString> {
        Ok(std::ffi::CString::new(
            directory.path().join(name).to_str().ok_or("path")?,
        )?)
    };
    let (outer_path, inner_path) = (path("outer")?, path("inner")?);
    kernel::initialize_production_hooks()?;
    let saved = kernel::SyscallProbe::table()?;

    // The outer handle is fetched under a probe that then ends.
    let old = kernel::SyscallProbe::start()?;
    old.set_quiescence(Duration::from_millis(100));
    let outer = kernel::fetch_open()?;
    let error = old
        .finish()
        .expect_err("restoration finished with a handle that was fetched and never invoked");
    assert!(error.contains("fetched a probe entry"), "{error}");
    assert_eq!(kernel::SyscallProbe::table()?, saved);

    let probe = kernel::SyscallProbe::start()?;
    probe.set_quiescence(Duration::from_millis(100));
    let seen = Rc::new(RefCell::new(Nested::default()));
    let _bound = bind_store(directory.path(), (0, 0))?;
    let hook_seen = Rc::clone(&seen);
    set_open_hook(Some(Box::new(move |_| {
        let mut nested = hook_seen.borrow_mut();
        let counts = || {
            (
                kernel::acquisitions_pending(),
                kernel::callbacks_in_flight(),
            )
        };
        nested.before = Some(counts());
        nested.inner = Some(
            kernel::fetch_open().map(|handle| handle.invoke(&inner_path, kernel::O_RDONLY, 0)),
        );
        nested.after = Some(counts());
        nested.plain = plain_fstat_entry()
            .ok()
            .map(|entry| call_plain_fstat(entry, -3));
    })));
    let result = outer.invoke(&outer_path, kernel::O_RDONLY, 0);
    set_open_hook(None);
    assert_eq!(result, (-1, ENOENT), "the outer call's own result");
    assert_eq!(
        *seen.borrow(),
        Nested {
            before: Some((0, 0)),
            inner: Some(Ok((-1, ENOENT))),
            after: Some((0, 0)),
            restoring: None,
            plain: Some((-1, EBADF)),
        }
    );
    let events = probe.finish()?;
    assert_eq!(events.failed_opens, 1, "{events:?}");
    assert!(
        matches!(
            events.open_failures[..],
            [kernel::OpenFailure {
                errno: ENOENT,
                foreign: false
            }]
        ) && events.opens.is_empty(),
        "only the inner call is observed: {events:?}"
    );
    assert_eq!(
        fstat_receipts(&events),
        [],
        "a plain call after the inner one returned was attributed to the probe armed now"
    );
    assert_eq!(kernel::SyscallProbe::table()?, saved);
    assert!(!kernel::armed());
    assert_eq!(kernel::acquisitions_pending(), 0);
    Ok(())
}

/// The same nesting under the probe the outer handle was fetched under, which another thread is
/// restoring while the outer call is still running. The outer call was admitted before the hook
/// ran and the inner one is admitted and settled inside it, each leaving its own receipt, and the
/// counts are exact in between: nothing pending, one callback in flight (the outer one). When the
/// inner call has returned the outer invocation is the one in progress again, so a plain call of
/// the entry fetched before the restoration, made once the restoration is waiting, is still
/// admitted and recorded into that generation: the restoration drains it.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn a_nested_invocation_keeps_the_outer_ownership_while_the_probe_restores() -> TestResult {
    use quotern_core::ingest::sqlite_ro::{bind_store, set_open_hook};
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::mpsc::channel;
    use std::time::Duration;

    const EBADF: std::ffi::c_int = 9;
    const ENOENT: std::ffi::c_int = 2;
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let path = |name: &str| -> TestResult<std::ffi::CString> {
        Ok(std::ffi::CString::new(
            directory.path().join(name).to_str().ok_or("path")?,
        )?)
    };
    let (outer_path, inner_path) = (path("outer")?, path("inner")?);
    kernel::initialize_production_hooks()?;
    let saved = kernel::SyscallProbe::table()?;

    let (armed_tx, armed_rx) = channel();
    let (restore_tx, restore_rx) = channel();
    let seen = Rc::new(RefCell::new(Nested::default()));
    let (result, finished) = std::thread::scope(|scope| -> TestResult<_> {
        let owner = scope.spawn(move || -> Result<kernel::Events, String> {
            let probe = kernel::SyscallProbe::start()?;
            probe.set_quiescence(Duration::from_secs(60));
            armed_tx.send(()).map_err(|error| error.to_string())?;
            restore_rx
                .recv_timeout(Duration::from_secs(60))
                .map_err(|error| error.to_string())?;
            probe.finish()
        });
        armed_rx.recv_timeout(Duration::from_secs(30))?;
        let outer = kernel::fetch_open()?;
        assert_eq!(kernel::acquisitions_pending(), 1);
        // Fetched now, called after the table has been put back.
        let plain_entry = plain_fstat_entry()?;
        let _bound = bind_store(directory.path(), (0, 0))?;
        let hook_seen = Rc::clone(&seen);
        set_open_hook(Some(Box::new(move |_| {
            let mut nested = hook_seen.borrow_mut();
            let counts = || {
                (
                    kernel::acquisitions_pending(),
                    kernel::callbacks_in_flight(),
                )
            };
            nested.before = Some(counts());
            nested.inner = Some(
                kernel::fetch_open().map(|handle| handle.invoke(&inner_path, kernel::O_RDONLY, 0)),
            );
            nested.after = Some(counts());
            nested.restoring = Some(match restore_tx.send(()) {
                Ok(()) => wait_until("the restoration to wait for the outer call", || {
                    kernel::restoring()
                })
                .map_err(|error| error.to_string()),
                Err(error) => Err(error.to_string()),
            });
            nested.plain = Some(call_plain_fstat(plain_entry, -3));
        })));
        let result = outer.invoke(&outer_path, kernel::O_RDONLY, 0);
        set_open_hook(None);
        Ok((result, owner.join().expect("owner")))
    })?;
    assert_eq!(result, (-1, ENOENT), "the outer call's own result");
    assert_eq!(
        *seen.borrow(),
        Nested {
            before: Some((0, 1)),
            inner: Some(Ok((-1, ENOENT))),
            after: Some((0, 1)),
            restoring: Some(Ok(())),
            plain: Some((-1, EBADF)),
        }
    );
    let events = finished?;
    assert_eq!(events.failed_opens, 2, "{events:?}");
    assert!(
        events.opens.is_empty()
            && events
                .open_failures
                .iter()
                .all(|failure| failure.errno == ENOENT && failure.foreign)
            && events.open_failures.len() == 2,
        "the inner and the outer call each leave a receipt: {events:?}"
    );
    assert_eq!(
        fstat_receipts(&events),
        [(-3, EBADF, true)],
        "a plain call after the inner one returned was not the outer invocation's"
    );
    assert_eq!(kernel::SyscallProbe::table()?, saved);
    assert!(!kernel::armed());
    assert_eq!(
        (
            kernel::acquisitions_pending(),
            kernel::callbacks_in_flight()
        ),
        (0, 0)
    );
    Ok(())
}

/// A connection that detached from the cached shared-memory node and attaches to it again is
/// validated again: the sidecar path may name another inode by then, and the node, kept alive by
/// another reader, still belongs to the old one.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn a_connection_that_detached_is_validated_again_when_it_attaches_to_the_cached_node() -> TestResult
{
    use std::ffi::c_void;

    const IOERR_SHMMAP: std::ffi::c_int = ffi_ioerr(21);
    const fn ffi_ioerr(extended: std::ffi::c_int) -> std::ffi::c_int {
        rusqlite::ffi::SQLITE_IOERR | (extended << 8)
    }
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let database = directory.path().join("opencode.db");
    let mut writer = start_writer(&database)?;
    let canonical = database.canonicalize()?;
    let shm = sidecar(&canonical, "-shm");
    let count = |connection: &Connection| -> rusqlite::Result<i64> {
        connection.query_row("SELECT COUNT(*) FROM records", [], |row| row.get(0))
    };
    reset_vfs_metrics()?;

    // `holder` keeps the node (and its mapping of the original sidecar inode) alive.
    let holder = open_canonical(&canonical)?;
    holder.execute_batch("BEGIN")?;
    assert_eq!(count(&holder)?, 1);
    let reader = open_canonical(&canonical)?;
    assert_eq!(count(&reader)?, 1);
    let accepted = vfs_metrics()?.readonly_shared_memory_maps;

    // The reader's own file handle, through which SQLite itself maps and unmaps shared memory.
    let mut file: *mut rusqlite::ffi::sqlite3_file = std::ptr::null_mut();
    // SAFETY: the handle is live; FILE_POINTER stores the pager's file pointer in the out slot.
    let code = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            reader.handle(),
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_FILE_POINTER,
            (&raw mut file).cast::<c_void>(),
        )
    };
    assert_eq!(code, rusqlite::ffi::SQLITE_OK);
    assert!(!file.is_null());
    // SAFETY: a live open file has live methods.
    let methods = unsafe { &*(*file).pMethods };
    let (map, unmap) = (
        methods.xShmMap.ok_or("xShmMap")?,
        methods.xShmUnmap.ok_or("xShmUnmap")?,
    );
    let remap = || -> (std::ffi::c_int, *mut c_void) {
        let mut region: *mut c_void = std::ptr::null_mut();
        // SAFETY: `file` is live; region 0 of 32 KiB without extension, as the WAL index asks.
        let code = unsafe { map(file, 0, 32_768, 0, &raw mut region) };
        (code, region)
    };

    // Detach, attach again with the sidecar unchanged: accepted from the cached node.
    // SAFETY: as above; a detach with no deletion.
    assert_eq!(unsafe { unmap(file, 0) }, rusqlite::ffi::SQLITE_OK);
    let (code, region) = remap();
    assert_eq!(code, rusqlite::ffi::SQLITE_READONLY);
    assert!(!region.is_null());
    assert_eq!(vfs_metrics()?.readonly_shared_memory_maps, accepted + 1);

    // Detach, replace the sidecar by another inode with identical bytes, attach again.
    // SAFETY: as above.
    assert_eq!(unsafe { unmap(file, 0) }, rusqlite::ffi::SQLITE_OK);
    let original = kernel::source_keys(&canonical)?;
    let parked = sidecar(&canonical, "-shm.parked");
    std::fs::rename(&shm, &parked)?;
    std::fs::copy(&parked, &shm)?;
    assert_ne!(
        kernel::source_keys(&canonical)?[kernel::SHM],
        original[kernel::SHM],
        "premise: new inode"
    );
    let (code, region) = remap();
    assert_eq!(
        code, IOERR_SHMMAP,
        "the cached node was served for the replaced sidecar"
    );
    assert!(region.is_null());
    let metrics = vfs_metrics()?;
    assert!(metrics.shared_memory_identity_rejected > 0, "{metrics:?}");
    assert_eq!(metrics.readonly_shared_memory_maps, accepted + 1);

    // SAFETY: as above.
    assert_eq!(unsafe { unmap(file, 0) }, rusqlite::ffi::SQLITE_OK);
    std::fs::remove_file(&shm)?;
    std::fs::rename(&parked, &shm)?;
    drop(reader);
    holder.execute_batch("COMMIT")?;
    drop(holder);
    writer.stop()?;
    Ok(())
}

/// The delegated open fails after the pre-open probe succeeded (the database vanished at the
/// instant of the open): the kernel's `errno` comes back unchanged.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn a_failed_delegated_open_hands_back_the_errno_of_the_kernel() -> TestResult {
    use quotern_core::ingest::sqlite_ro::{MetadataMeter, set_open_hook};

    const ENOENT: std::ffi::c_int = 2;
    let _guard = vfs_test_guard();
    let directory = tempdir()?;
    let database = directory.path().join("opencode.db");
    let mut writer = start_writer(&database)?;
    let canonical = database.canonicalize()?;
    let parked = sidecar(&canonical, ".parked");
    drop(open_canonical(&canonical)?); // first-use initialisation
    let probe = kernel::SyscallProbe::start()?;
    let (hook_database, hook_parked) = (canonical.clone(), parked.clone());
    set_open_hook(Some(Box::new(move |path| {
        if path == hook_database {
            let _ = std::fs::rename(&hook_database, &hook_parked);
        }
    })));
    let meter = MetadataMeter::begin(10_000);
    let failed = open_canonical(&canonical);
    let (_, refused) = meter.state();
    drop(meter);
    set_open_hook(None);
    std::fs::rename(&parked, &canonical)?; // the database is back
    assert!(failed.is_err() && !refused, "{:?} {refused}", failed.err());
    let events = probe.finish()?;
    assert!(!events.open_failures.is_empty(), "{events:?}");
    assert_eq!(events.failed_opens, events.open_failures.len());
    assert!(
        events
            .open_failures
            .iter()
            .all(|failure| failure.errno == ENOENT && !failure.foreign),
        "{events:?}"
    );
    writer.stop()?;
    Ok(())
}
