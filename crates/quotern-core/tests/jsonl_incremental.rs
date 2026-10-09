//! Bounded incremental JSONL acquisition for Codex: the `SourceFs::read_tail` provider contract,
//! pending and oversize tails, truncation/rotation, closed-app appends, unchanged passes, and the
//! bounded frontier (current dated path, retained iterator, restart, reserve, missing, capacity,
//! per-pass budgets and the uncovered-lookup cost) on a 20,001-entry historical backlog.

use std::collections::HashMap;
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use quotern_core::domain::{
    ConsentState, FailureCode, PassCounters, PassOutcome, PassReport, SourceAuthorization,
    SourceKind,
};
use quotern_core::ingest::Engine;
use quotern_core::ingest::fs::{
    BoundedRead, DirEntries, FileStamp, RealSourceFs, RecordingFs, SourceFs, physical_operations,
};
use quotern_core::ingest::sqlite_ro::OpenError;
use quotern_core::limits::MAX_FILE_BYTES;
use rusqlite::{Connection, StatementStatus};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const STEPS: &str = include_str!("../../../Fixtures/harness/codex/incremental/steps.json");
const EXPECTED: &str = include_str!("../../../Fixtures/harness/codex/incremental/expected.json");
const BASIC_FILE: &str = "sessions/2026/03/29/rollout-2026-03-29T09-00-00-basic.jsonl";
const DAY_NOW: i64 = 1_774_785_600_000;
const HISTORICAL: usize = 20_001;

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

fn reported_bytes(codex: bool, session: &str, response: &str, input: u32) -> Vec<u8> {
    if codex {
        format!(
            "{}\n{}\n",
            json!({"type": "session_meta", "payload": {"id": session, "cli_version": "0.153.0"}}),
            json!({"timestamp": "2026-03-29T08:01:00Z", "type": "token_usage_record",
                "payload": {"thread_id": session, "session_id": session, "response_id": response,
                    "usage": {"input_tokens": input, "total_tokens": input}}})
        )
        .into_bytes()
    } else {
        serde_json::to_vec(&json!({"role": "assistant", "time": {"created": DAY_NOW},
            "tokens": {"input": input, "output": 0, "reasoning": 0,
                "cache": {"read": 0, "write": 0}, "total": input}}))
        .expect("literal usage JSON")
    }
}

fn reported_path(codex: bool, name: &str) -> String {
    if codex {
        format!("sessions/old/{name}.jsonl")
    } else {
        format!("storage/message/own/{name}.json")
    }
}

fn reported_engine(
    world: &World,
    fs: ReversedFs,
    codex: bool,
) -> TestResult<(Engine<ReversedFs>, String)> {
    if codex {
        world.engine(fs)
    } else {
        let mut engine = Engine::open(&world.data, &world.home);
        let id = engine
            .attach_opencode(fs, &world.root, enabled(), SourceKind::Custom)
            .map_err(|report| format!("attach_opencode failed: {report:?}"))?;
        Ok((engine, id))
    }
}

fn source_membership(connection: &Connection, id: &str) -> TestResult<Vec<(String, String)>> {
    let mut statement = connection.prepare(
        "SELECT relative_path, file_state FROM source_files WHERE source_id = ?1 ORDER BY relative_path",
    )?;
    Ok(statement
        .query_map([id], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<_, _>>()?)
}

fn assert_last_good(
    world: &World,
    engine: &Engine<ReversedFs>,
    id: &str,
    report: &PassReport,
    last_good: i64,
) -> TestResult {
    assert_eq!(report.last_good_ms, Some(last_good));
    assert_eq!(
        count(
            &world.history()?,
            "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
            &[&id]
        )?,
        last_good
    );
    let snapshot = serde_json::to_value(
        engine
            .today_snapshot("UTC", DAY_NOW + 1000)
            .map_err(|error| format!("{error:?}"))?,
    )?;
    assert_eq!(
        snapshot["source_reported"][0]["input"]["last_good_ms"],
        last_good
    );
    Ok(())
}

struct World {
    _directory: tempfile::TempDir,
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

    fn append(&self, relative: &str, bytes: &[u8]) -> TestResult {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(self.root.join(relative))?;
        file.write_all(bytes)?;
        Ok(())
    }

    fn basic(&self) -> TestResult<PathBuf> {
        self.put(
            BASIC_FILE,
            &std::fs::read(fixtures().join(format!("harness/codex/basic/{BASIC_FILE}")))?,
        )
    }

    fn engine<F: SourceFs>(&self, fs: F) -> TestResult<(Engine<F>, String)> {
        let mut engine = Engine::open(&self.data, &self.home);
        let id = engine
            .attach_codex(fs, &self.root, enabled(), SourceKind::Custom)
            .map_err(|report| format!("attach_codex failed: {report:?}"))?;
        Ok((engine, id))
    }

    fn history(&self) -> TestResult<Connection> {
        Ok(Connection::open(self.data.join("history.sqlite"))?)
    }

    /// The 20,001-entry historical backlog: empty rollout files directly in `sessions/`, created
    /// newest first, beside today's dated file `BASIC_FILE`.
    fn backlog(&self) -> TestResult {
        let sessions = self.root.join("sessions");
        std::fs::create_dir_all(&sessions)?;
        for index in (0..HISTORICAL).rev() {
            std::fs::File::create(sessions.join(historical_name(index)))?;
        }
        Ok(())
    }
}

fn historical_name(index: usize) -> String {
    format!("rollout-2025-01-01T00-00-00-h{index:05}.jsonl")
}

fn count(
    connection: &Connection,
    sql: &str,
    parameters: &[&dyn rusqlite::ToSql],
) -> TestResult<i64> {
    Ok(connection.query_row(sql, parameters, |row| row.get(0))?)
}

fn rows(connection: &Connection, source_id: &str) -> TestResult<Vec<Value>> {
    let mut statement = connection.prepare(
        "SELECT session_id, message_id, occurred_at_ms, input_tokens, cache_read_tokens, \
         cache_write_tokens, output_tokens, reasoning_tokens, total_tokens, mirror_path, revision \
         FROM usage_events WHERE source_id = ?1 ORDER BY occurred_at_ms, event_key",
    )?;
    let found = statement
        .query_map([source_id], |row| {
            Ok(json!({
                "session_id": row.get::<_, String>(0)?,
                "response_id": row.get::<_, String>(1)?,
                "occurred_at_ms": row.get::<_, i64>(2)?,
                "input_tokens": row.get::<_, Option<i64>>(3)?,
                "cache_read_tokens": row.get::<_, Option<i64>>(4)?,
                "cache_write_tokens": row.get::<_, Option<i64>>(5)?,
                "output_tokens": row.get::<_, Option<i64>>(6)?,
                "reasoning_tokens": row.get::<_, Option<i64>>(7)?,
                "total_tokens": row.get::<_, Option<i64>>(8)?,
                "mirror_path": row.get::<_, String>(9)?,
                "revision": row.get::<_, i64>(10)?,
            }))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(found)
}

fn file_state(
    connection: &Connection,
    source_id: &str,
    relative: &str,
) -> TestResult<(i64, Option<String>, String)> {
    Ok(connection.query_row(
        "SELECT byte_offset, tail_state, file_state FROM source_files \
         WHERE source_id = ?1 AND relative_path = ?2",
        [source_id, relative],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?)
}

fn by_source_pending<F: SourceFs>(engine: &Engine<F>, source_id: &str) -> TestResult<bool> {
    let entries = engine.source_entries()?;
    let entry = entries
        .iter()
        .find(|entry| entry.source_id == source_id)
        .ok_or("no source entry")?;
    Ok(entry.pending_partial)
}

fn assert_within_caps(counters: &PassCounters, label: &str) {
    assert!(counters.entries <= 20_000, "{label}: {counters:?}");
    assert!(counters.stat_calls <= 40_000, "{label}: {counters:?}");
    assert!(counters.header_reads <= 256, "{label}: {counters:?}");
    assert!(counters.directory_opens <= 64, "{label}: {counters:?}");
    assert!(counters.bytes_read <= 67_108_864, "{label}: {counters:?}");
}

/// A test double for a filesystem whose directory order is the reverse of name order, so every
/// historical rollout in `sessions/` is listed before the dated `sessions/2026` subtree. Listings
/// are counted per directory. Every other operation is the recording filesystem's.
#[derive(Clone)]
struct ReversedFs {
    inner: RecordingFs,
    listings: Arc<Mutex<HashMap<PathBuf, u32>>>,
    directory_fault: Arc<Mutex<Option<PathBuf>>>,
    metadata_fault: Arc<Mutex<Option<PathBuf>>>,
    iterator_fault: Arc<Mutex<Option<PathBuf>>>,
    missing_listing: Arc<Mutex<Option<PathBuf>>>,
    confirmation_budget: Arc<Mutex<Option<PathBuf>>>,
    metadata_budget: Arc<Mutex<Option<PathBuf>>>,
    budget_at_file: Arc<Mutex<Option<(PathBuf, PathBuf)>>>,
    remove_at_metadata: Arc<Mutex<Option<PathBuf>>>,
    acquisition_budget: Arc<Mutex<Option<PathBuf>>>,
    bounded_swap: Arc<Mutex<Option<DataSwap>>>,
    bounded_acquisitions: Arc<Mutex<Vec<(u64, u64, usize)>>>,
    restore_root_at_metadata: Arc<Mutex<Option<(PathBuf, PathBuf, PathBuf)>>>,
    tail_reads: Arc<Mutex<Vec<(PathBuf, u64, usize)>>>,
    tail_attempts: Arc<Mutex<Vec<PathBuf>>>,
    tail_fault: Arc<Mutex<Option<PathBuf>>>,
    listing_swap: Arc<Mutex<Option<ListingSwap>>>,
}

struct ListingSwap {
    root: PathBuf,
    saved: PathBuf,
    budget_target: PathBuf,
    restore_before_proof: Option<PathBuf>,
}

struct DataSwap {
    target: PathBuf,
    data: PathBuf,
    saved: PathBuf,
}

impl ReversedFs {
    fn new() -> Self {
        Self {
            inner: RecordingFs::new(),
            listings: Arc::new(Mutex::new(HashMap::new())),
            directory_fault: Arc::new(Mutex::new(None)),
            metadata_fault: Arc::new(Mutex::new(None)),
            iterator_fault: Arc::new(Mutex::new(None)),
            missing_listing: Arc::new(Mutex::new(None)),
            confirmation_budget: Arc::new(Mutex::new(None)),
            metadata_budget: Arc::new(Mutex::new(None)),
            budget_at_file: Arc::new(Mutex::new(None)),
            remove_at_metadata: Arc::new(Mutex::new(None)),
            acquisition_budget: Arc::new(Mutex::new(None)),
            bounded_swap: Arc::new(Mutex::new(None)),
            bounded_acquisitions: Arc::new(Mutex::new(Vec::new())),
            restore_root_at_metadata: Arc::new(Mutex::new(None)),
            tail_reads: Arc::new(Mutex::new(Vec::new())),
            tail_attempts: Arc::new(Mutex::new(Vec::new())),
            tail_fault: Arc::new(Mutex::new(None)),
            listing_swap: Arc::new(Mutex::new(None)),
        }
    }

    fn listings_of(&self, path: &Path) -> u32 {
        self.listings
            .lock()
            .map(|listings| listings.get(path).copied().unwrap_or(0))
            .unwrap_or(0)
    }
}

impl SourceFs for ReversedFs {
    fn canonicalize(&self, path: &Path, counters: &mut PassCounters) -> io::Result<PathBuf> {
        self.inner.canonicalize(path, counters)
    }

    fn metadata(&self, path: &Path, counters: &mut PassCounters) -> io::Result<std::fs::Metadata> {
        let mut restoration = self
            .restore_root_at_metadata
            .lock()
            .map_err(|_| io::Error::other("restoration lock"))?;
        if restoration
            .as_ref()
            .is_some_and(|(root, _, _)| root == path)
        {
            let (root, moved, rejected) = restoration
                .take()
                .ok_or_else(|| io::Error::other("restoration target"))?;
            std::fs::rename(&root, rejected)?;
            std::fs::rename(moved, &root)?;
        }
        drop(restoration);
        let mut boundary = self
            .budget_at_file
            .lock()
            .map_err(|_| io::Error::other("file budget lock"))?;
        if boundary.as_ref().is_some_and(|(file, _)| file == path) {
            let (_, target) = boundary
                .take()
                .ok_or_else(|| io::Error::other("file budget target"))?;
            *self
                .metadata_budget
                .lock()
                .map_err(|_| io::Error::other("metadata budget lock"))? = Some(target);
        }
        drop(boundary);
        let mut removal = self
            .remove_at_metadata
            .lock()
            .map_err(|_| io::Error::other("removal lock"))?;
        if removal.as_deref() == Some(path) {
            std::fs::remove_file(path)?;
            removal.take();
        }
        drop(removal);
        if self
            .metadata_budget
            .lock()
            .map_err(|_| io::Error::other("metadata budget lock"))?
            .as_deref()
            == Some(path)
        {
            while counters.stat_calls < 40_000 {
                self.inner.metadata(path, counters)?;
            }
        }
        let metadata = self.inner.metadata(path, counters)?;
        if self
            .metadata_fault
            .lock()
            .map_err(|_| io::Error::other("metadata fault lock"))?
            .as_deref()
            == Some(path)
        {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        Ok(metadata)
    }

    fn read_dir(&self, path: &Path, counters: &mut PassCounters) -> io::Result<DirEntries> {
        if self
            .acquisition_budget
            .lock()
            .map_err(|_| io::Error::other("acquisition budget lock"))?
            .as_deref()
            == Some(path)
        {
            while counters.stat_calls < 39_999 {
                self.inner.metadata(path, counters)?;
            }
            return self.inner.read_dir(path, counters);
        }
        if self
            .confirmation_budget
            .lock()
            .map_err(|_| io::Error::other("confirmation budget lock"))?
            .as_deref()
            == Some(path)
        {
            while counters.stat_calls < 40_000 {
                self.inner.metadata(path, counters)?;
            }
            return Err(io::Error::from(io::ErrorKind::NotFound));
        }
        if self
            .directory_fault
            .lock()
            .map_err(|_| io::Error::other("directory fault lock"))?
            .as_deref()
            == Some(path)
        {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        if self
            .missing_listing
            .lock()
            .map_err(|_| io::Error::other("listing fault lock"))?
            .as_deref()
            == Some(path)
        {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        }
        if let Ok(mut listings) = self.listings.lock() {
            *listings.entry(path.to_path_buf()).or_insert(0) += 1;
        }
        let mut entries: Vec<io::Result<PathBuf>> = self.inner.read_dir(path, counters)?.collect();
        let mut swap = self
            .listing_swap
            .lock()
            .map_err(|_| io::Error::other("listing swap lock"))?;
        if swap.as_ref().is_some_and(|swap| swap.root == path) {
            assert!(
                entries.is_empty(),
                "native empty EOF must precede the root swap"
            );
            let swap = swap
                .take()
                .ok_or_else(|| io::Error::other("listing swap target"))?;
            std::fs::rename(&swap.root, &swap.saved)?;
            std::fs::create_dir(&swap.root)?;
            *self
                .metadata_budget
                .lock()
                .map_err(|_| io::Error::other("budget lock"))? = Some(swap.budget_target);
            if let Some(rejected) = swap.restore_before_proof {
                *self
                    .restore_root_at_metadata
                    .lock()
                    .map_err(|_| io::Error::other("restoration lock"))? =
                    Some((swap.root, swap.saved, rejected));
            }
        }
        drop(swap);
        entries.sort_by(|left, right| match (left, right) {
            (Ok(left), Ok(right)) => right.cmp(left),
            (Ok(_), Err(_)) => std::cmp::Ordering::Less,
            (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
            (Err(_), Err(_)) => std::cmp::Ordering::Equal,
        });
        if self
            .iterator_fault
            .lock()
            .map_err(|_| io::Error::other("iterator fault lock"))?
            .as_deref()
            == Some(path)
        {
            entries.insert(1, Err(io::Error::from(io::ErrorKind::PermissionDenied)));
        }
        Ok(Box::new(entries.into_iter()))
    }

    fn read_header(&self, path: &Path, counters: &mut PassCounters) -> io::Result<Vec<u8>> {
        self.inner.read_header(path, counters)
    }

    fn read_bounded(
        &self,
        path: &Path,
        max_bytes: usize,
        counters: &mut PassCounters,
    ) -> io::Result<BoundedRead> {
        let before = physical_operations().bytes_requested;
        let read = self.inner.read_bounded(path, max_bytes, counters)?;
        let mut swap = self
            .bounded_swap
            .lock()
            .map_err(|_| io::Error::other("swap lock"))?;
        if swap.as_ref().is_some_and(|swap| swap.target == path) {
            let after = physical_operations().bytes_requested;
            assert!(
                after > before && !read.bytes.is_empty(),
                "real bounded acquisition must precede the swap"
            );
            self.bounded_acquisitions
                .lock()
                .map_err(|_| io::Error::other("acquisition trace lock"))?
                .push((before, after, read.bytes.len()));
            let swap = swap.take().ok_or_else(|| io::Error::other("swap target"))?;
            std::fs::rename(&swap.data, &swap.saved)?;
            std::fs::create_dir(&swap.data)?;
            std::fs::write(swap.data.join("sentinel"), b"substitute unchanged")?;
        }
        Ok(read)
    }

    fn open_sqlite(&self, canonical_path: &Path) -> Result<Connection, OpenError> {
        self.inner.open_sqlite(canonical_path)
    }

    fn read_tail(
        &self,
        path: &Path,
        offset: u64,
        max_bytes: usize,
        counters: &mut PassCounters,
    ) -> io::Result<BoundedRead> {
        self.tail_attempts
            .lock()
            .map_err(|_| io::Error::other("tail attempts lock"))?
            .push(path.to_path_buf());
        if self
            .tail_fault
            .lock()
            .map_err(|_| io::Error::other("tail fault lock"))?
            .as_deref()
            == Some(path)
        {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        let read = self.inner.read_tail(path, offset, max_bytes, counters)?;
        self.tail_reads
            .lock()
            .map_err(|_| io::Error::other("tail reads lock"))?
            .push((path.to_path_buf(), offset, read.bytes.len()));
        Ok(read)
    }
}

/// A filesystem that implements only the required methods and keeps the provided `read_tail`.
struct PlainFs;

impl SourceFs for PlainFs {
    fn canonicalize(&self, path: &Path, counters: &mut PassCounters) -> io::Result<PathBuf> {
        RealSourceFs.canonicalize(path, counters)
    }

    fn metadata(&self, path: &Path, counters: &mut PassCounters) -> io::Result<std::fs::Metadata> {
        RealSourceFs.metadata(path, counters)
    }

    fn read_dir(&self, path: &Path, counters: &mut PassCounters) -> io::Result<DirEntries> {
        RealSourceFs.read_dir(path, counters)
    }

    fn read_header(&self, path: &Path, counters: &mut PassCounters) -> io::Result<Vec<u8>> {
        RealSourceFs.read_header(path, counters)
    }

    fn read_bounded(
        &self,
        path: &Path,
        max_bytes: usize,
        counters: &mut PassCounters,
    ) -> io::Result<BoundedRead> {
        RealSourceFs.read_bounded(path, max_bytes, counters)
    }

    fn open_sqlite(&self, canonical_path: &Path) -> Result<Connection, OpenError> {
        RealSourceFs.open_sqlite(canonical_path)
    }
}

fn base_bytes() -> TestResult<Vec<u8>> {
    Ok(std::fs::read(fixtures().join(
        "harness/codex/incremental/base/sessions/2026/03/29/rollout-2026-03-29T09-00-00-inc.jsonl",
    ))?)
}

/// (device, inode, size, mtime ns) from an independent `stat`.
fn independent_stamp(path: &Path) -> TestResult<(u64, u64, u64, i64)> {
    let metadata = std::fs::metadata(path)?;
    Ok((
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime() * 1_000_000_000 + metadata.mtime_nsec(),
    ))
}

#[test]
fn read_tail_provider_contract() -> TestResult {
    let steps = json(STEPS)?;
    let expected = json(EXPECTED)?;
    let base = base_bytes()?;
    let world = World::new()?;
    let relative = steps["relative_path"].as_str().ok_or("path")?;
    let path = world.root.join(relative);
    let recording = RecordingFs::new();
    let mut recorded_calls = 0;
    for step in steps["steps"].as_array().ok_or("steps")? {
        let number = &step["step"];
        let length = usize::try_from(step["length"].as_u64().ok_or("length")?)?;
        world.put(relative, &base[..length])?;
        let reads = expected["tail_reads"]
            .as_array()
            .ok_or("tail_reads")?
            .iter()
            .flat_map(|read| [(read, read["length"].as_u64()), (read, Some(1 << 20))])
            .chain(
                expected["provider_extra"]
                    .as_array()
                    .ok_or("provider_extra")?
                    .iter()
                    .map(|read| (read, read["cap"].as_u64())),
            )
            .filter(|(read, _)| read["step"] == *number);
        for (read, cap) in reads {
            let cap = usize::try_from(cap.ok_or("cap")?)?;
            let offset = read["offset"].as_u64().ok_or("offset")?;
            for (label, fs) in [
                ("real", &RealSourceFs as &dyn SourceFs),
                ("recording", &recording as &dyn SourceFs),
            ] {
                let mut counters = PassCounters::default();
                let requested = physical_operations().bytes_requested;
                let tail = fs.read_tail(&path, offset, cap, &mut counters)?;
                assert_eq!(json!(tail.bytes.len()), read["length"], "{label} {read}");
                assert_eq!(
                    std::str::from_utf8(&tail.bytes)?,
                    read["bytes"].as_str().ok_or("bytes")?,
                    "{label}: exact bytes"
                );
                let stamp = independent_stamp(&path)?;
                for observed in [tail.before, tail.after] {
                    assert_eq!(
                        (
                            observed.device,
                            observed.inode,
                            observed.size,
                            observed.mtime_ns
                        ),
                        stamp,
                        "{label}"
                    );
                }
                assert!(
                    counters.stat_calls > 0,
                    "{label}: the open and verification are metered"
                );
                assert_eq!(
                    physical_operations().bytes_requested - requested,
                    tail.bytes.len() as u64,
                    "{label}: exactly the returned bytes are requested"
                );
                if label == "recording" {
                    recorded_calls += 1;
                }
            }
        }
    }
    assert_eq!(recording.metrics().tail_reads, recorded_calls);
    let mut counters = PassCounters::default();
    let refused = PlainFs
        .read_tail(&path, 0, 10, &mut counters)
        .err()
        .ok_or("default served a read")?;
    assert_eq!(refused.kind(), io::ErrorKind::Unsupported);
    assert_eq!(counters, PassCounters::default());
    Ok(())
}

fn assert_rows(actual: &[Value], expected: &Value, label: &str) -> TestResult {
    let expected = expected.as_array().ok_or("events")?;
    assert_eq!(actual.len(), expected.len(), "{label}: {actual:?}");
    for (row, want) in actual.iter().zip(expected) {
        for (name, value) in want.as_object().ok_or("event")? {
            assert_eq!(&row[name], value, "{label}: {name}");
        }
    }
    Ok(())
}

#[test]
fn partial_tail_then_newline_counts_once() -> TestResult {
    let steps = json(STEPS)?;
    let expected = json(EXPECTED)?;
    let base = base_bytes()?;
    let world = World::new()?;
    let relative = steps["relative_path"].as_str().ok_or("path")?;
    let recording = RecordingFs::new();
    let (mut engine, id) = world.engine(recording.clone())?;
    let mut written = 0;
    for (step, after) in steps["steps"]
        .as_array()
        .ok_or("steps")?
        .iter()
        .zip(expected["after_step"].as_array().ok_or("after_step")?)
    {
        let length = usize::try_from(step["length"].as_u64().ok_or("length")?)?;
        if written == 0 {
            world.put(relative, &base[..length])?;
        } else if length > written {
            world.append(relative, &base[written..length])?;
        }
        written = length;
        let tail_reads = recording.metrics().tail_reads;
        let report = engine.pass(&id, enabled(), step["now_ms"].as_i64().ok_or("now")?);
        let label = format!("step {}", step["step"]);
        let reads: Vec<&Value> = expected["tail_reads"]
            .as_array()
            .ok_or("tail_reads")?
            .iter()
            .filter(|read| read["step"] == step["step"])
            .collect();
        assert_eq!(
            recording.metrics().tail_reads - tail_reads,
            reads.len() as u64,
            "{label}"
        );
        assert_eq!(
            json!(report.counters.bytes_read),
            after["bytes_read"],
            "{label}: {report:?}"
        );
        assert_eq!(
            report.counters.bytes_read,
            reads
                .iter()
                .filter_map(|read| read["length"].as_u64())
                .sum::<u64>(),
            "{label}: bytes read are the oracle's tail reads"
        );
        assert_eq!(
            json!(report.records_committed),
            after["records_committed"],
            "{label}"
        );
        assert_eq!(json!(report.outcome), after["outcome"], "{label}");
        let connection = world.history()?;
        assert_rows(&rows(&connection, &id)?, &after["events"], &label)?;
        let (offset, tail, _) = file_state(&connection, &id, relative)?;
        assert_eq!(json!(offset), after["byte_offset"], "{label}");
        assert_eq!(json!(tail), after["tail_state"], "{label}");
        assert_eq!(
            json!(by_source_pending(&engine, &id)?),
            after["pending_partial"],
            "{label}"
        );
    }
    Ok(())
}

#[test]
fn pending_tail_survives_reopen() -> TestResult {
    let expected = json(EXPECTED)?;
    let base = base_bytes()?;
    let world = World::new()?;
    let relative = "sessions/2026/03/29/rollout-2026-03-29T09-00-00-inc.jsonl";
    world.put(relative, &base[..700])?;
    let id = {
        let (mut engine, id) = world.engine(RealSourceFs)?;
        assert_eq!(engine.pass(&id, enabled(), DAY_NOW).records_committed, 1);
        id
    };
    let (offset, tail, _) = file_state(&world.history()?, &id, relative)?;
    assert_eq!(
        (offset, tail.as_deref()),
        (551, Some("pending")),
        "the pending tail is durable"
    );
    {
        let (mut engine, _) = world.engine(RealSourceFs)?;
        let unchanged = engine.pass(&id, enabled(), DAY_NOW + 1000);
        assert_eq!(
            (unchanged.records_committed, unchanged.counters.bytes_read),
            (0, 0)
        );
        assert_eq!(file_state(&world.history()?, &id, relative)?.0, 551);
        assert!(by_source_pending(&engine, &id)?);
    }
    world.append(relative, &base[700..])?;
    let (mut engine, _) = world.engine(RealSourceFs)?;
    assert!(
        by_source_pending(&engine, &id)?,
        "reopened with the pending flag"
    );
    let report = engine.pass(&id, enabled(), DAY_NOW + 60_000);
    assert_eq!(report.records_committed, 1, "{report:?}");
    assert_eq!(report.counters.bytes_read, 915);
    assert_rows(
        &rows(&world.history()?, &id)?,
        &expected["after_step"][1]["events"],
        "after reopen",
    )?;
    assert!(!by_source_pending(&engine, &id)?);
    Ok(())
}

#[test]
fn oversize_tail_discarded_once() -> TestResult {
    let base = base_bytes()?;
    let world = World::new()?;
    let relative = "sessions/2026/03/29/rollout-2026-03-29T09-00-00-inc.jsonl";
    let mut text = base[..551].to_vec();
    text.resize(551 + MAX_FILE_BYTES + 10, b'x');
    world.put(relative, &text)?;
    let (mut engine, id) = world.engine(RealSourceFs)?;
    let mut rejected = 0;
    let mut now = DAY_NOW;
    for _ in 0..16 {
        let report = engine.pass(&id, enabled(), now);
        now += 60_000;
        assert!(
            report.counters.bytes_read <= MAX_FILE_BYTES as u64,
            "{report:?}"
        );
        rejected += report.counters.rejected_records;
        if report.counters.rejected_records > 0 {
            assert_eq!(
                report.failure,
                Some(FailureCode::RecordTooLarge),
                "{report:?}"
            );
        }
    }
    assert_eq!(rejected, 1, "the oversize tail is rejected exactly once");
    let (offset, tail, _) = file_state(&world.history()?, &id, relative)?;
    assert_eq!(
        offset,
        i64::try_from(text.len())?,
        "every discarded byte is behind the cursor"
    );
    assert_eq!(tail.as_deref(), Some("discarding"));
    // The newline ends the discarded line; the next complete line counts.
    world.append(relative, b"\n")?;
    world.append(relative, &base[551..])?;
    let mut rejected = 0;
    let mut committed = 0;
    for _ in 0..16 {
        let report = engine.pass(&id, enabled(), now);
        now += 1000;
        assert_within_caps(&report.counters, "changed oversize drain");
        rejected += report.counters.rejected_records;
        committed += report.records_committed;
    }
    assert_eq!(rejected, 1, "a changed stamp starts a new stable scan");
    assert_eq!(committed, 1);
    let responses: Vec<Value> = rows(&world.history()?, &id)?
        .into_iter()
        .map(|row| row["response_id"].clone())
        .collect();
    assert_eq!(
        responses,
        vec![json!("resp_inc_001"), json!("resp_inc_002")]
    );
    assert_eq!(file_state(&world.history()?, &id, relative)?.1, None);
    drop(engine);
    let (mut engine, reopened) = world.engine(RealSourceFs)?;
    assert_eq!(id, reopened);
    assert_eq!(engine.pass(&id, enabled(), now + 1000).records_committed, 0);
    let snapshot = serde_json::to_value(
        engine
            .today_snapshot("UTC", now + 1000)
            .map_err(|e| format!("{e:?}"))?,
    )?;
    let reported = snapshot["source_reported"]
        .as_array()
        .ok_or("reported")?
        .iter()
        .find(|entry| entry["source_id"] == id)
        .ok_or("source")?;
    assert_eq!(
        reported["input"]["completeness"], "partial",
        "discarded invalid line leaves durable uncertainty"
    );
    Ok(())
}

/// Byte offset just past the `n`th newline of `bytes`.
fn after_line(bytes: &[u8], n: usize) -> TestResult<usize> {
    bytes
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b'\n')
        .nth(n - 1)
        .map(|(index, _)| index + 1)
        .ok_or_else(|| "short file".into())
}

#[test]
fn truncation_rotation_reread_without_duplicate() -> TestResult {
    let world = World::new()?;
    let path = world.basic()?;
    let full = std::fs::read(&path)?;
    let (mut engine, id) = world.engine(RealSourceFs)?;
    engine.pass(&id, enabled(), DAY_NOW);
    let first = rows(&world.history()?, &id)?;
    assert_eq!(first.len(), 3);
    // Truncate in place to the end of the first record line (line 4).
    let cut = after_line(&full, 4)?;
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)?
        .set_len(u64::try_from(cut)?)?;
    let report = engine.pass(&id, enabled(), DAY_NOW + 1_000);
    assert_eq!(report.records_committed, 0, "{report:?}");
    assert_eq!(
        file_state(&world.history()?, &id, BASIC_FILE)?.0,
        i64::try_from(cut)?
    );
    assert_eq!(
        rows(&world.history()?, &id)?,
        first,
        "history kept, nothing duplicated"
    );
    // The same inode grows back to the full content.
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)?
        .write_all(&full[cut..])?;
    let report = engine.pass(&id, enabled(), DAY_NOW + 2_000);
    assert_eq!(report.records_committed, 0, "{report:?}");
    assert_eq!(rows(&world.history()?, &id)?, first);
    // Rotation: the file moves aside and a new file takes its path.
    let rotated = "sessions/2026/03/29/rollout-2026-03-29T09-00-00-rotated.jsonl";
    std::fs::rename(&path, world.root.join(rotated))?;
    let header = &full[..after_line(&full, 1)?];
    let fresh = String::from_utf8(header.to_vec())?
        + "{\"timestamp\":\"2026-03-29T09:04:00.000Z\",\"type\":\"token_usage_record\",\"payload\":{\"thread_id\":\"0195f000-0000-7000-8000-00000000b001\",\"turn_id\":\"t4\",\"session_id\":\"0195f000-0000-7000-8000-00000000b001\",\"root_turn_id\":\"t4\",\"response_id\":\"resp_basic_004\",\"usage\":{\"input_tokens\":7,\"total_tokens\":7}}}\n";
    world.put(BASIC_FILE, fresh.as_bytes())?;
    let report = engine.pass(&id, enabled(), DAY_NOW + 3_000);
    assert_eq!(report.records_committed, 1, "{report:?}");
    let after = rows(&world.history()?, &id)?;
    assert_eq!(after.len(), 4);
    for row in &after {
        assert_eq!(row["revision"], 1, "{row}");
        assert_eq!(
            row["mirror_path"], BASIC_FILE,
            "the byte-smaller path holds every record"
        );
    }
    Ok(())
}

#[test]
fn append_while_closed_counted_by_reconcile() -> TestResult {
    let world = World::new()?;
    world.basic()?;
    let id = {
        let (mut engine, id) = world.engine(RealSourceFs)?;
        assert_eq!(engine.pass(&id, enabled(), DAY_NOW).records_committed, 3);
        id
    };
    world.append(
        BASIC_FILE,
        b"{\"timestamp\":\"2026-03-29T09:04:00.000Z\",\"type\":\"token_usage_record\",\"payload\":{\"thread_id\":\"0195f000-0000-7000-8000-00000000b001\",\"turn_id\":\"t4\",\"session_id\":\"0195f000-0000-7000-8000-00000000b001\",\"root_turn_id\":\"t4\",\"response_id\":\"resp_basic_004\",\"usage\":{\"input_tokens\":7,\"total_tokens\":7}}}\n",
    )?;
    let (mut engine, again) = world.engine(RealSourceFs)?;
    assert_eq!(again, id);
    let report = engine.pass(&id, enabled(), DAY_NOW + 60_000);
    assert_eq!(
        report.records_committed, 1,
        "one explicit reconcile counts the append once"
    );
    let found = rows(&world.history()?, &id)?;
    assert_eq!(found.len(), 4);
    assert!(found.iter().all(|row| row["revision"] == 1));
    assert_eq!(
        engine
            .pass(&id, enabled(), DAY_NOW + 120_000)
            .records_committed,
        0
    );
    Ok(())
}

#[test]
fn unchanged_reconcile_pass_reads_nothing() -> TestResult {
    let world = World::new()?;
    world.basic()?;
    let recording = RecordingFs::new();
    let (mut engine, id) = world.engine(recording.clone())?;
    engine.pass(&id, enabled(), DAY_NOW);
    let before = recording.metrics();
    let report = engine.pass(&id, enabled(), DAY_NOW + 1_000);
    let after = recording.metrics();
    assert_eq!(report.outcome, PassOutcome::Consistent, "{report:?}");
    assert_eq!(report.records_committed, 0);
    assert_eq!(report.counters.bytes_read, 0);
    assert_eq!(after.tail_reads, before.tail_reads, "no content opened");
    assert_eq!(after.bounded_reads, before.bounded_reads);
    assert_eq!(after.header_reads, before.header_reads);
    assert_eq!(after.sqlite_opens, before.sqlite_opens);
    assert!(
        after.stat_calls > before.stat_calls,
        "metadata work is still done and charged"
    );
    assert!(
        report.counters.stat_calls > 0 && report.counters.entries > 0,
        "{report:?}"
    );
    Ok(())
}

fn pass<F: SourceFs>(engine: &mut Engine<F>, id: &str, now_ms: i64) -> PassReport {
    engine.pass(id, enabled(), now_ms)
}

fn historical_rows(world: &World, source_id: &str) -> TestResult<i64> {
    count(
        &world.history()?,
        "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND relative_path LIKE 'sessions/rollout-2025-%'",
        &[&source_id],
    )
}

#[test]
fn today_path_beyond_readdir_cap() -> TestResult {
    let world = World::new()?;
    world.backlog()?;
    world.basic()?;
    let fs = ReversedFs::new();
    let (mut engine, id) = world.engine(fs.clone())?;
    let report = pass(&mut engine, &id, DAY_NOW);
    assert_eq!(report.outcome, PassOutcome::CatchingUp, "{report:?}");
    assert_eq!(
        report.records_committed, 3,
        "today's dated file is counted in the first pass"
    );
    assert_eq!(rows(&world.history()?, &id)?.len(), 3);
    assert!(
        historical_rows(&world, &id)? < i64::try_from(HISTORICAL)?,
        "the backlog is not finished"
    );
    assert_within_caps(&report.counters, "first pass");
    Ok(())
}

/// Passes until the generation completes; returns every report.
fn drain<F: SourceFs>(
    engine: &mut Engine<F>,
    id: &str,
    mut now_ms: i64,
    limit: usize,
) -> TestResult<Vec<PassReport>> {
    let mut reports = Vec::new();
    for _ in 0..limit {
        let report = pass(engine, id, now_ms);
        now_ms += 60_000;
        let done = report.outcome == PassOutcome::Consistent;
        reports.push(report);
        if done {
            return Ok(reports);
        }
    }
    Err(format!("not drained in {limit} passes: {reports:?}").into())
}

#[test]
fn retained_iterator_drains_backlog() -> TestResult {
    let world = World::new()?;
    world.backlog()?;
    world.basic()?;
    let fs = ReversedFs::new();
    let (mut engine, id) = world.engine(fs.clone())?;
    let reports = drain(&mut engine, &id, DAY_NOW, 4)?;
    assert!(reports.len() >= 2, "the backlog needs more than one pass");
    assert_eq!(
        fs.listings_of(&world.root.join("sessions")),
        1,
        "the giant listing is read once"
    );
    assert_eq!(historical_rows(&world, &id)?, i64::try_from(HISTORICAL)?);
    Ok(())
}

#[test]
fn restart_rewalk_is_bounded() -> TestResult {
    let world = World::new()?;
    world.backlog()?;
    world.basic()?;
    let fs = ReversedFs::new();
    let id = {
        let (mut engine, id) = world.engine(fs.clone())?;
        let report = pass(&mut engine, &id, DAY_NOW);
        assert_eq!(report.outcome, PassOutcome::CatchingUp);
        id
    };
    // Restart: the incomplete listing is rebuilt from its beginning, once, in bounded passes.
    let (mut engine, _) = world.engine(fs.clone())?;
    let reports = drain(&mut engine, &id, DAY_NOW + 60_000, 4)?;
    for (index, report) in reports.iter().enumerate() {
        assert_within_caps(&report.counters, &format!("restart pass {index}"));
        assert_eq!(
            report.records_committed, 0,
            "the rewalk commits nothing again: {report:?}"
        );
    }
    assert_eq!(
        fs.listings_of(&world.root.join("sessions")),
        2,
        "one rewalk after one restart"
    );
    assert_eq!(historical_rows(&world, &id)?, i64::try_from(HISTORICAL)?);
    Ok(())
}

fn appended_record(index: usize) -> String {
    format!(
        "{{\"timestamp\":\"2026-03-29T10:{:02}:00.000Z\",\"type\":\"token_usage_record\",\"payload\":{{\"thread_id\":\"0195f000-0000-7000-8000-00000000b001\",\"turn_id\":\"t\",\"session_id\":\"0195f000-0000-7000-8000-00000000b001\",\"root_turn_id\":\"t\",\"response_id\":\"resp_live_{index}\",\"usage\":{{\"input_tokens\":1,\"total_tokens\":1}}}}}}\n",
        index % 60
    )
}

#[test]
fn stable_backlog_not_starved() -> TestResult {
    let world = World::new()?;
    world.backlog()?;
    world.basic()?;
    let fs = ReversedFs::new();
    let (mut engine, id) = world.engine(fs.clone())?;
    let mut drained = false;
    for index in 0..4 {
        world.append(BASIC_FILE, appended_record(index).as_bytes())?;
        let report = pass(&mut engine, &id, DAY_NOW + i64::try_from(index)? * 60_000);
        assert_eq!(
            report.records_committed,
            if index == 0 { 4 } else { 1 },
            "{report:?}"
        );
        assert_within_caps(&report.counters, "live pass");
        if report.outcome == PassOutcome::Consistent {
            drained = true;
            break;
        }
    }
    assert!(
        drained,
        "current writes never starve the historical backlog"
    );
    assert_eq!(historical_rows(&world, &id)?, i64::try_from(HISTORICAL)?);
    Ok(())
}

#[test]
fn unvisited_never_missing() -> TestResult {
    let world = World::new()?;
    let path = world.basic()?;
    let fs = ReversedFs::new();
    let (mut engine, id) = world.engine(fs.clone())?;
    assert_eq!(
        pass(&mut engine, &id, DAY_NOW).outcome,
        PassOutcome::Consistent
    );
    world.backlog()?;
    std::fs::remove_file(&path)?;
    let report = pass(&mut engine, &id, DAY_NOW + 60_000);
    assert_eq!(report.outcome, PassOutcome::CatchingUp, "{report:?}");
    let missing =
        "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND file_state = 'missing'";
    assert_eq!(
        count(&world.history()?, missing, &[&id])?,
        0,
        "nothing is missing before the terminal generation"
    );
    assert_eq!(file_state(&world.history()?, &id, BASIC_FILE)?.2, "present");
    drain(&mut engine, &id, DAY_NOW + 120_000, 4)?;
    assert_eq!(file_state(&world.history()?, &id, BASIC_FILE)?.2, "missing");
    assert_eq!(count(&world.history()?, missing, &[&id])?, 1);
    assert_eq!(
        rows(&world.history()?, &id)?.len(),
        3,
        "observed history is kept"
    );
    Ok(())
}

#[test]
fn terminal_generation_marks_missing() -> TestResult {
    let world = World::new()?;
    let path = world.basic()?;
    let other = "sessions/2026/03/29/rollout-other.jsonl";
    world.put(other, &std::fs::read(&path)?)?;
    let (mut engine, id) = world.engine(RealSourceFs)?;
    assert_eq!(
        pass(&mut engine, &id, DAY_NOW).outcome,
        PassOutcome::Consistent
    );
    let settled = pass(&mut engine, &id, DAY_NOW + 1_000);
    let projection = engine.snapshot(&id, &settled)?.projection;
    std::fs::remove_file(world.root.join(other))?;
    let report = pass(&mut engine, &id, DAY_NOW + 2_000);
    assert_eq!(report.outcome, PassOutcome::Consistent, "{report:?}");
    assert_eq!(file_state(&world.history()?, &id, other)?.2, "missing");
    assert_eq!(file_state(&world.history()?, &id, BASIC_FILE)?.2, "present");
    assert_eq!(
        engine.snapshot(&id, &report)?.projection,
        projection,
        "events are never deleted"
    );
    Ok(())
}

#[test]
fn capacity_failure_preserves_history() -> TestResult {
    let world = World::new()?;
    let path = world.basic()?;
    let (mut engine, id) = world.engine(RealSourceFs)?;
    pass(&mut engine, &id, DAY_NOW);
    let history = rows(&world.history()?, &id)?;
    std::fs::remove_file(&path)?;
    // Directories that each hold many subdirectories: listing them enqueues faster than the
    // per-pass directory opens can drain, until the 4,096-directory queue ceiling refuses one.
    for parent in 0..8 {
        for child in 0..1_000 {
            std::fs::create_dir_all(
                world
                    .root
                    .join(format!("sessions/2025/d{parent}/s{child:03}")),
            )?;
        }
    }
    for step in 0..2 {
        let report = pass(&mut engine, &id, DAY_NOW + 60_000 * (step + 1));
        if step == 0 {
            // The queue ceiling refused a directory: visible, never a silent drop.
            assert_eq!(
                report.failure,
                Some(FailureCode::LimitExceeded),
                "{report:?}"
            );
        }
        assert_ne!(report.outcome, PassOutcome::Consistent, "{report:?}");
        assert_within_caps(&report.counters, "capacity pass");
    }
    assert_eq!(
        rows(&world.history()?, &id)?,
        history,
        "history is never evicted"
    );
    assert_eq!(
        file_state(&world.history()?, &id, BASIC_FILE)?.2,
        "present",
        "never classified missing"
    );
    Ok(())
}

#[test]
fn every_pass_metadata_budget() -> TestResult {
    let world = World::new()?;
    world.backlog()?;
    world.basic()?;
    let fs = ReversedFs::new();
    let (mut engine, id) = world.engine(fs.clone())?;
    let mut now = DAY_NOW;
    for index in 0..4 {
        let before = fs.inner.metrics();
        let report = pass(&mut engine, &id, now);
        now += 60_000;
        let after = fs.inner.metrics();
        println!("pass {index}: {:?} {:?}", report.outcome, report.counters);
        assert_within_caps(&report.counters, &format!("pass {index}"));
        assert_eq!(
            after.stat_calls - before.stat_calls,
            u64::from(report.counters.stat_calls),
            "pass {index}: every physical metadata call is charged"
        );
        assert!(after.max_open_directories <= 8);
        if report.outcome == PassOutcome::Consistent {
            return Ok(());
        }
    }
    Err("the backlog never drained".into())
}

#[test]
fn uncovered_lookup_cost_recorded() -> TestResult {
    let world = World::new()?;
    world.backlog()?;
    world.basic()?;
    let appended = "rollout-2026-03-29T11-00-00-appended.jsonl";
    world.put(
        &format!("sessions/2026/03/29/{appended}"),
        &std::fs::read(fixtures().join(format!(
            "harness/codex/headers/sessions/2026/03/29/{appended}"
        )))?,
    )?;
    let fs = ReversedFs::new();
    let (mut engine, id) = world.engine(fs)?;
    drain(&mut engine, &id, DAY_NOW, 4)?;
    let connection = world.history()?;
    let files = count(
        &connection,
        "SELECT COUNT(*) FROM source_files WHERE source_id = ?1",
        &[&id],
    )?;
    assert!(files > i64::try_from(HISTORICAL)?, "{files}");
    let sql = quotern_core::store::uncovered_lookup_sql();
    let plan: Vec<String> = connection
        .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?
        .query_map(rusqlite::params![&id, 0, 0], |row| row.get::<_, String>(3))?
        .collect::<Result<_, _>>()?;
    println!("uncovered lookup plan: {plan:?}");
    assert!(
        plan.iter()
            .any(|detail| detail.starts_with("SEARCH source_files")
                && detail.contains("source_id=?")),
        "a source_id prefix search, never a table scan: {plan:?}"
    );
    let mut statement = connection.prepare(sql)?;
    for (label, start, end, hit) in [
        (
            "miss 2025-01-02",
            1_735_776_000_000_i64,
            1_735_862_400_000_i64,
            false,
        ),
        ("hit 2026-03-29", 1_774_742_400_000, 1_774_828_800_000, true),
    ] {
        statement.reset_status(StatementStatus::VmStep);
        let started = std::time::Instant::now();
        let found = statement.exists(rusqlite::params![&id, start, end])?;
        let elapsed = started.elapsed();
        let steps = statement.get_status(StatementStatus::VmStep);
        println!(
            "uncovered lookup {label}: rows={files} found={found} vm_steps={steps} micros={}",
            elapsed.as_micros()
        );
        assert_eq!(found, hit, "{label}");
        assert!(steps > 0);
    }
    let snapshot = serde_json::to_value(
        engine
            .today_snapshot("UTC", DAY_NOW)
            .map_err(|error| format!("{error:?}"))?,
    )?;
    let entry = snapshot["source_reported"]
        .as_array()
        .and_then(|entries| entries.iter().find(|entry| entry["source_id"] == json!(id)))
        .ok_or("entry")?;
    assert_eq!(
        entry["input"]["completeness"], "partial",
        "the uncovered range makes the day partial"
    );
    Ok(())
}

#[test]
fn first_line_acquisitions_obey_header_ceiling_and_drain() -> TestResult {
    let world = World::new()?;
    let header =
        b"{\"type\":\"session_meta\",\"payload\":{\"id\":\"own\",\"cli_version\":\"0.153.0\"}}\n";
    for index in 0..600 {
        world.put(&format!("sessions/rollout-header-{index:03}.jsonl"), header)?;
    }
    let fs = RecordingFs::new();
    let (mut engine, id) = world.engine(fs.clone())?;
    for step in 0..8 {
        let before = fs.metrics();
        let report = pass(&mut engine, &id, DAY_NOW + step * 1000);
        assert_within_caps(&report.counters, "header pass");
        assert_eq!(
            fs.metrics().tail_reads - before.tail_reads,
            u64::from(report.counters.header_reads),
            "every first-line acquisition is charged"
        );
        if report.outcome == PassOutcome::Consistent {
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND header_id = 'own'",
                    &[&id]
                )?,
                600
            );
            return Ok(());
        }
        assert_eq!(report.counters.header_reads, 256);
    }
    Err("header backlog never drained".into())
}

#[test]
fn failed_historical_directory_remains_pending_across_reopen() -> TestResult {
    let world = World::new()?;
    world.backlog()?;
    world.basic()?;
    let blocked = world.root.join("sessions/zzblocked");
    let relative = "sessions/zzblocked/rollout-hidden.jsonl";
    world.put(relative, &base_bytes()?)?;
    let fs = ReversedFs::new();
    *fs.directory_fault.lock().map_err(|_| "fault lock")? = Some(blocked.clone());
    let id = {
        let (mut engine, id) = world.engine(fs.clone())?;
        let first = pass(&mut engine, &id, DAY_NOW);
        assert_ne!(first.outcome, PassOutcome::Consistent);
        assert!(
            count(
                &world.history()?,
                "SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1 AND relative_path = 'sessions/zzblocked'",
                &[&id]
            )? > 0,
            "failed directory must retain retry work: {first:?}"
        );
        id
    };
    let (mut engine, reopened) = world.engine(fs.clone())?;
    assert_eq!(id, reopened);
    let retry = pass(&mut engine, &id, DAY_NOW + 1000);
    assert_ne!(
        retry.outcome,
        PassOutcome::Consistent,
        "unread subtree cannot finalize: {retry:?}"
    );
    *fs.directory_fault.lock().map_err(|_| "fault lock")? = None;
    drain(&mut engine, &id, DAY_NOW + 2000, 8)?;
    assert_eq!(file_state(&world.history()?, &id, relative)?.2, "present");
    assert_eq!(
        pass(&mut engine, &id, DAY_NOW + 10_000).records_committed,
        0
    );
    Ok(())
}

#[test]
fn nested_tree_holds_real_directory_iterators_within_ceiling() -> TestResult {
    let world = World::new()?;
    for branch in 0..12 {
        for child in 0..12 {
            world.put(
                &format!("sessions/b{branch:02}/c{child:02}/rollout-empty.jsonl"),
                b"",
            )?;
        }
    }
    let fs = RecordingFs::new();
    let (mut engine, id) = world.engine(fs.clone())?;
    let mut reports = 0;
    for step in 0..8 {
        let report = pass(&mut engine, &id, DAY_NOW + step * 1000);
        reports += 1;
        assert_within_caps(&report.counters, "unbuffered nested tree");
        assert!(fs.metrics().max_open_directories <= 8);
        if report.outcome == PassOutcome::Consistent {
            assert!(
                fs.metrics().max_open_directories > 1,
                "real iterators overlapped"
            );
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND adapter_state = 'codex_jsonl'",
                    &[&id]
                )?,
                144
            );
            println!(
                "unbuffered nested tree: {reports} passes, {:?}",
                fs.metrics()
            );
            return Ok(());
        }
    }
    Err("nested tree never drained".into())
}

#[test]
fn codex_unchanged_unfinished_scan_resumes_after_reopen() -> TestResult {
    let world = World::new()?;
    let relative = "sessions/2026/03/29/rollout-2026-03-29T09-00-00-inc.jsonl";
    let base = base_bytes()?;
    let mut bytes = base[..551].to_vec();
    for _ in 0..2 {
        bytes.extend_from_slice(b"{}");
        bytes.extend(vec![b' '; 599_997]);
        bytes.push(b'\n');
    }
    bytes.extend_from_slice(&base[551..]);
    world.put(relative, &bytes)?;
    let (mut engine, id) = world.engine(RealSourceFs)?;
    let first = engine.pass(&id, enabled(), DAY_NOW);
    assert_eq!(first.outcome, PassOutcome::CatchingUp);
    assert_eq!(first.counters.bytes_read, 1_048_576);
    assert_eq!(first.records_committed, 1);
    assert_eq!(file_state(&world.history()?, &id, relative)?.0, 600_551);
    drop(engine);
    let (mut engine, reopened) = world.engine(RealSourceFs)?;
    assert_eq!(id, reopened);
    let next = engine.pass(&id, enabled(), DAY_NOW + 1000);
    assert_eq!(next.counters.header_reads, 0);
    assert_eq!(next.counters.bytes_read, 600_364);
    assert_eq!(next.records_committed, 1);
    assert_eq!(next.outcome, PassOutcome::Consistent);
    let expected = json(EXPECTED)?;
    assert_rows(
        &rows(&world.history()?, &id)?,
        &expected["after_step"][1]["events"],
        "stable drain",
    )?;
    assert_eq!(
        engine
            .pass(&id, enabled(), DAY_NOW + 2000)
            .counters
            .bytes_read,
        0
    );
    world.append(relative, b"{}\n")?;
    let changed = engine.pass(&id, enabled(), DAY_NOW + 3000);
    assert_eq!(
        (changed.counters.header_reads, changed.counters.bytes_read),
        (1, 1_048_576)
    );
    assert_eq!(changed.records_committed, 0);
    assert_eq!(changed.outcome, PassOutcome::CatchingUp);
    let drain = engine.pass(&id, enabled(), DAY_NOW + 4000);
    assert_within_caps(&drain.counters, "changed drain");
    assert_eq!(drain.outcome, PassOutcome::Consistent);
    assert_eq!(drain.records_committed, 0);
    assert_rows(
        &rows(&world.history()?, &id)?,
        &expected["after_step"][1]["events"],
        "changed drain",
    )?;
    assert_eq!(
        engine
            .pass(&id, enabled(), DAY_NOW + 5000)
            .counters
            .bytes_read,
        0
    );
    Ok(())
}

#[test]
fn jsonl_line_bound_discriminates_one_mib_from_file_cap() -> TestResult {
    for (length, accepted) in [(1_048_577, false), (1_048_576, true)] {
        let world = World::new()?;
        let base = base_bytes()?;
        let header_end = after_line(&base, 1)?;
        let mut bytes = base[..header_end].to_vec();
        let record = &base[header_end..551];
        assert_eq!(record.last(), Some(&b'\n'));
        let mut padded = record[..record.len() - 1].to_vec();
        padded.resize(length - 1, b' ');
        padded.push(b'\n');
        assert_eq!(padded.len(), length);
        bytes.extend(padded);
        bytes.extend_from_slice(&base[551..]);
        let relative = "sessions/rollout-line-bound.jsonl";
        world.put(relative, &bytes)?;
        let (mut engine, id) = world.engine(RealSourceFs)?;
        let mut rejected = 0;
        let mut committed = 0;
        let mut most_read = 0;
        for step in 0..5 {
            let report = engine.pass(&id, enabled(), DAY_NOW + step * 1000);
            assert_within_caps(&report.counters, "line boundary");
            most_read = most_read.max(report.counters.bytes_read);
            rejected += report.counters.rejected_records;
            committed += report.records_committed;
            if report.counters.rejected_records > 0 {
                assert_eq!(report.failure, Some(FailureCode::RecordTooLarge));
            }
        }
        assert_eq!(rejected, u32::from(!accepted));
        assert!(most_read <= 1_048_576);
        assert_eq!(committed, if accepted { 2 } else { 1 });
        let found = rows(&world.history()?, &id)?;
        assert_eq!(found.len(), if accepted { 2 } else { 1 });
        assert_eq!(
            found.last().ok_or("following row")?["response_id"],
            "resp_inc_002"
        );
        let settled = engine.pass(&id, enabled(), DAY_NOW + 6000);
        assert_eq!(
            (
                settled.records_committed,
                settled.counters.bytes_read,
                settled.counters.rejected_records
            ),
            (0, 0, 0)
        );
    }
    Ok(())
}

#[test]
fn duplicate_lane_keeps_unfinished_suffix_pending() -> TestResult {
    for reopen in [false, true] {
        let world = World::new()?;
        for index in 0..4097 {
            world.put(&format!("sessions/rollout-known-{index:04}.jsonl"), b"")?;
        }
        let (mut engine, id) = world.engine(RealSourceFs)?;
        drain(&mut engine, &id, DAY_NOW, 4)?;
        let connection = world.history()?;
        assert_eq!(
            count(
                &connection,
                "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND adapter_state = 'codex_jsonl'",
                &[&id]
            )?,
            4097
        );
        let relative: String = connection.query_row(
            "SELECT relative_path FROM source_files WHERE source_id = ?1 AND adapter_state = 'codex_jsonl' ORDER BY visit_seq, mtime_ns DESC, relative_path LIMIT 1",
            [&id], |row| row.get(0),
        )?;
        let base = base_bytes()?;
        let mut bytes = base[..551].to_vec();
        for _ in 0..3 {
            bytes.extend_from_slice(b"{}");
            bytes.extend(vec![b' '; 599_997]);
            bytes.push(b'\n');
        }
        bytes.extend_from_slice(&base[551..]);
        world.put(&relative, &bytes)?;
        let first = pass(&mut engine, &id, DAY_NOW + 10_000);
        assert_eq!(first.outcome, PassOutcome::CatchingUp);
        assert_eq!(first.records_committed, 1);
        assert_eq!(file_state(&connection, &id, &relative)?.0, 600_551);
        if reopen {
            drop(engine);
            (engine, _) = world.engine(RealSourceFs)?;
        }
        let second = pass(&mut engine, &id, DAY_NOW + 11_000);
        assert_eq!(
            second.outcome,
            PassOutcome::CatchingUp,
            "unread suffix, reopen={reopen}: {second:?}"
        );
        assert_eq!(
            count(
                &connection,
                "SELECT dirty FROM sources WHERE source_id = ?1",
                &[&id]
            )?,
            1
        );
        assert_eq!(file_state(&connection, &id, &relative)?.0, 1_200_551);
        assert_eq!(second.records_committed, 0);
        let rest = drain(&mut engine, &id, DAY_NOW + 12_000, 4)?;
        assert_eq!(
            rest.iter()
                .map(|report| report.records_committed)
                .sum::<u32>(),
            1
        );
        assert_eq!(
            file_state(&connection, &id, &relative)?.0,
            i64::try_from(bytes.len())?
        );
        let mut expected = json(EXPECTED)?["after_step"][1]["events"].clone();
        for event in expected.as_array_mut().ok_or("events")? {
            event["mirror_path"] = json!(relative);
        }
        assert_rows(&rows(&connection, &id)?, &expected, "suffix once")?;
        assert_eq!(
            pass(&mut engine, &id, DAY_NOW + 30_000).records_committed,
            0
        );
    }
    Ok(())
}

#[test]
fn pruned_failed_directory_drains_before_and_after_reopen() -> TestResult {
    for reopen in [false, true] {
        let world = World::new()?;
        let relative = "sessions/zzblocked/rollout-hidden.jsonl";
        world.put(relative, &base_bytes()?)?;
        let fs = ReversedFs::new();
        let (mut engine, id) = world.engine(fs.clone())?;
        drain(&mut engine, &id, DAY_NOW, 4)?;
        let before = rows(&world.history()?, &id)?;
        assert_eq!(before.len(), 2);
        let blocked = world.root.join("sessions/zzblocked");
        *fs.directory_fault.lock().map_err(|_| "fault lock")? = Some(blocked.clone());
        let failed = pass(&mut engine, &id, DAY_NOW + 10_000);
        assert_ne!(failed.outcome, PassOutcome::Consistent);
        assert!(
            count(
                &world.history()?,
                "SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1 AND relative_path = 'sessions/zzblocked'",
                &[&id]
            )? > 0
        );
        if reopen {
            drop(engine);
            (engine, _) = world.engine(fs.clone())?;
        }
        *fs.directory_fault.lock().map_err(|_| "fault lock")? = None;
        std::fs::remove_dir_all(&blocked)?;
        let reports = drain(&mut engine, &id, DAY_NOW + 11_000, 4)?;
        assert_eq!(
            reports
                .iter()
                .map(|report| report.records_committed)
                .sum::<u32>(),
            0
        );
        assert_eq!(rows(&world.history()?, &id)?, before);
        assert_eq!(file_state(&world.history()?, &id, relative)?.2, "missing");
        assert_eq!(
            count(
                &world.history()?,
                "SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1",
                &[&id]
            )?,
            0
        );
        drop(engine);
        let (mut engine, reopened) = world.engine(fs)?;
        assert_eq!(id, reopened);
        assert_eq!(
            pass(&mut engine, &id, DAY_NOW + 20_000).outcome,
            PassOutcome::Consistent
        );
        assert_eq!(rows(&world.history()?, &id)?, before);
    }
    Ok(())
}

#[test]
fn iterator_and_metadata_failures_retain_work_across_reopen() -> TestResult {
    for fault in [
        "iterator",
        "directory_metadata",
        "entry_metadata",
        "listing_not_found",
    ] {
        let world = World::new()?;
        let directory = world.root.join("sessions/old");
        let header = b"{\"type\":\"session_meta\",\"payload\":{\"id\":\"own\",\"cli_version\":\"0.153.0\"}}\n";
        let record = |response: &str| {
            format!(
                "{{\"timestamp\":\"2026-03-29T08:01:00Z\",\"type\":\"token_usage_record\",\"payload\":{{\"thread_id\":\"own\",\"session_id\":\"own\",\"response_id\":\"{response}\",\"usage\":{{\"input_tokens\":7,\"total_tokens\":7}}}}}}\n"
            )
        };
        for name in ["a", "z"] {
            let bytes = [header.as_slice(), record(name).as_bytes()].concat();
            world.put(&format!("sessions/old/rollout-{name}.jsonl"), &bytes)?;
        }
        let fs = ReversedFs::new();
        let (mut engine, id) = world.engine(fs.clone())?;
        drain(&mut engine, &id, DAY_NOW, 4)?;
        // Both records already exist; a retry must never mark the unvisited one missing.
        let before = rows(&world.history()?, &id)?;
        world.put(
            "sessions/old/rollout-new.jsonl",
            &[header.as_slice(), record("new").as_bytes()].concat(),
        )?;
        match fault {
            "iterator" => {
                *fs.iterator_fault.lock().map_err(|_| "fault lock")? = Some(directory.clone())
            }
            "entry_metadata" => {
                *fs.metadata_fault.lock().map_err(|_| "fault lock")? =
                    Some(directory.join("rollout-new.jsonl"))
            }
            "listing_not_found" => {
                *fs.missing_listing.lock().map_err(|_| "fault lock")? = Some(directory.clone())
            }
            _ => *fs.directory_fault.lock().map_err(|_| "fault lock")? = Some(directory.clone()),
        }
        let failed = pass(&mut engine, &id, DAY_NOW + 1000);
        assert_ne!(
            failed.outcome,
            PassOutcome::Consistent,
            "{fault}: {failed:?}"
        );
        assert!(
            count(
                &world.history()?,
                "SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1 AND relative_path = 'sessions/old'",
                &[&id]
            )? > 0,
            "{fault}"
        );
        assert_eq!(
            count(
                &world.history()?,
                "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND file_state = 'missing'",
                &[&id]
            )?,
            0,
            "{fault}"
        );
        if fault == "iterator" {
            assert_eq!(
                fs.tail_reads
                    .lock()
                    .map_err(|_| "reads lock")?
                    .iter()
                    .filter(|(path, _, _)| path == &directory.join("rollout-z.jsonl"))
                    .count(),
                1
            );
            assert_eq!(
                failed.counters.entries, 4,
                "root, sessions, valid entry, iterator error"
            );
        }
        drop(engine);
        if fault == "directory_metadata" {
            *fs.directory_fault.lock().map_err(|_| "fault lock")? = None;
            *fs.metadata_fault.lock().map_err(|_| "fault lock")? = Some(directory.clone());
        }
        let (mut engine, reopened) = world.engine(fs.clone())?;
        assert_eq!(id, reopened);
        let retry = pass(&mut engine, &id, DAY_NOW + 2000);
        assert_ne!(
            retry.outcome,
            PassOutcome::Consistent,
            "durable {fault}: {retry:?}"
        );
        assert!(
            count(
                &world.history()?,
                "SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1 AND relative_path = 'sessions/old'",
                &[&id]
            )? > 0
        );
        assert_eq!(
            count(
                &world.history()?,
                "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND file_state = 'missing'",
                &[&id]
            )?,
            0
        );
        *fs.directory_fault.lock().map_err(|_| "fault lock")? = None;
        *fs.metadata_fault.lock().map_err(|_| "fault lock")? = None;
        *fs.iterator_fault.lock().map_err(|_| "fault lock")? = None;
        *fs.missing_listing.lock().map_err(|_| "fault lock")? = None;
        let reports = drain(&mut engine, &id, DAY_NOW + 3000, 4)?;
        assert_eq!(
            reports
                .iter()
                .map(|report| report.records_committed)
                .sum::<u32>(),
            1,
            "{fault}"
        );
        let after = rows(&world.history()?, &id)?;
        assert_eq!(after.len(), 3);
        assert!(
            before.iter().all(|row| after.contains(row)),
            "retained {fault}"
        );
        assert_eq!(
            count(
                &world.history()?,
                "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                &[&id]
            )?,
            21
        );
        assert_eq!(
            pass(&mut engine, &id, DAY_NOW + 10_000).records_committed,
            0
        );
    }
    Ok(())
}

#[test]
fn nonempty_current_and_historical_lanes_saturate_byte_budget() -> TestResult {
    let world = World::new()?;
    let fs = ReversedFs::new();
    let mut total_source_bytes = 0;
    for lane in ["current", "historical"] {
        for index in 0..40 {
            let header = "{\"type\":\"session_meta\",\"payload\":{\"id\":\"own\",\"cli_version\":\"0.153.0\"}}\n";
            let record = format!(
                "{{\"timestamp\":\"2026-03-29T08:01:00Z\",\"type\":\"token_usage_record\",\"payload\":{{\"thread_id\":\"own\",\"session_id\":\"own\",\"response_id\":\"{lane}-{index}\",\"usage\":{{\"input_tokens\":7,\"total_tokens\":11}}}}}}"
            );
            let mut bytes = format!("{header}{record}").into_bytes();
            bytes.resize(1_048_575, b' ');
            bytes.push(b'\n');
            let relative = if lane == "current" {
                format!("sessions/2026/03/29/rollout-current-{index:02}.jsonl")
            } else {
                format!("sessions/rollout-historical-{index:02}.jsonl")
            };
            total_source_bytes += bytes.len();
            world.put(&relative, &bytes)?;
        }
    }
    assert_eq!(total_source_bytes, 83_886_080);
    let (mut engine, id) = world.engine(fs.clone())?;
    let before = physical_operations();
    let first = pass(&mut engine, &id, DAY_NOW);
    let physical = physical_operations();
    assert_eq!(
        physical.bytes_requested - before.bytes_requested,
        67_108_864
    );
    assert_eq!(first.counters.bytes_read, 67_108_864);
    assert_within_caps(&first.counters, "saturated first pass");
    assert!(physical.metadata - before.metadata <= 40_000);
    assert!(physical.directory_opens - before.directory_opens <= 64);
    assert!(physical.directory_yields - before.directory_yields <= 20_000);
    assert_eq!(first.outcome, PassOutcome::CatchingUp);
    assert_eq!(first.records_committed, 64);
    assert_last_good(&world, &engine, &id, &first, DAY_NOW)?;
    let reads = fs.tail_reads.lock().map_err(|_| "reads lock")?;
    for lane in ["current", "historical"] {
        let lane_bytes: usize = reads
            .iter()
            .filter(|(path, _, _)| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().contains(lane))
            })
            .map(|(_, _, length)| length)
            .sum();
        assert_eq!(lane_bytes, 33_554_432, "{lane} reserve");
    }
    assert!(reads.iter().all(|(_, _, length)| *length <= 1_048_576));
    drop(reads);
    assert!(
        count(
            &world.history()?,
            "SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1",
            &[&id]
        )? > 0
    );
    assert_eq!(
        count(
            &world.history()?,
            "SELECT dirty FROM sources WHERE source_id = ?1",
            &[&id]
        )?,
        1
    );
    drop(engine);
    let (mut engine, reopened) = world.engine(fs.clone())?;
    assert_eq!(id, reopened);
    let mut committed = 64;
    for step in 1..5 {
        let before = physical_operations();
        let report = pass(&mut engine, &id, DAY_NOW + step * 1000);
        let physical = physical_operations();
        assert!(physical.bytes_requested - before.bytes_requested <= 67_108_864);
        assert!(physical.metadata - before.metadata <= 40_000);
        assert!(physical.directory_opens - before.directory_opens <= 64);
        assert!(physical.directory_yields - before.directory_yields <= 20_000);
        assert_within_caps(&report.counters, "saturated continuation");
        committed += report.records_committed;
        assert!(
            fs.tail_reads
                .lock()
                .map_err(|_| "reads lock")?
                .iter()
                .all(|(_, _, length)| *length <= 1_048_576)
        );
        assert!(fs.inner.metrics().max_open_directories <= 8);
        if report.outcome == PassOutcome::Consistent {
            assert_eq!(committed, 80);
            assert_eq!(rows(&world.history()?, &id)?.len(), 80);
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                    &[&id]
                )?,
                560
            );
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT SUM(total_tokens) FROM usage_events WHERE source_id = ?1",
                    &[&id]
                )?,
                880
            );
            let settled = pass(&mut engine, &id, DAY_NOW + 10_000);
            assert_eq!(
                (settled.records_committed, settled.counters.bytes_read),
                (0, 0)
            );
            return Ok(());
        }
    }
    Err("nonempty workload did not drain".into())
}

#[test]
fn source_root_disappearance_during_listing_never_completes() -> TestResult {
    let world = World::new()?;
    world.basic()?;
    let fs = ReversedFs::new();
    let (mut engine, id) = world.engine(fs.clone())?;
    drain(&mut engine, &id, DAY_NOW, 4)?;
    let before = rows(&world.history()?, &id)?;
    let root = world.root.clone();
    let moved = world._directory.path().join("moved-root");
    let target = moved.clone();
    fs.inner.on_boundary(move |kind, path| {
        if kind == quotern_core::ingest::fs::OpenKind::Directory && path == root {
            std::fs::rename(&root, &target).expect("move test root at listing boundary");
        }
    });
    let report = pass(&mut engine, &id, DAY_NOW + 1000);
    std::fs::rename(moved, &world.root)?;
    fs.inner.on_boundary(|_, _| {});
    assert_ne!(
        report.outcome,
        PassOutcome::Consistent,
        "root loss is not subtree pruning: {report:?}"
    );
    assert_eq!(rows(&world.history()?, &id)?, before);
    assert_eq!(
        count(
            &world.history()?,
            "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND file_state = 'missing'",
            &[&id]
        )?,
        0
    );
    drain(&mut engine, &id, DAY_NOW + 2000, 4)?;
    Ok(())
}

#[test]
fn pruned_deferred_suffix_drains_and_preserves_numeric_history() -> TestResult {
    let world = World::new()?;
    let relative = "sessions/rollout-deferred.jsonl";
    let base = base_bytes()?;
    let mut bytes = base[..551].to_vec();
    for _ in 0..2 {
        bytes.extend_from_slice(b"{}");
        bytes.extend(vec![b' '; 599_997]);
        bytes.push(b'\n');
    }
    bytes.extend_from_slice(&base[551..]);
    let path = world.put(relative, &bytes)?;
    let (mut engine, id) = world.engine(RealSourceFs)?;
    let first = pass(&mut engine, &id, DAY_NOW);
    assert_eq!(first.outcome, PassOutcome::CatchingUp);
    assert_eq!(first.records_committed, 1);
    let before = rows(&world.history()?, &id)?;
    std::fs::remove_file(path)?;
    drain(&mut engine, &id, DAY_NOW + 1000, 4)?;
    assert_eq!(rows(&world.history()?, &id)?, before);
    assert_eq!(
        file_state(&world.history()?, &id, relative)?,
        (600_551, None, "present".to_owned())
    );
    drain(&mut engine, &id, DAY_NOW + 5000, 4)?;
    assert_eq!(
        file_state(&world.history()?, &id, relative)?,
        (600_551, None, "missing".to_owned())
    );
    drop(engine);
    let (mut engine, reopened) = world.engine(RealSourceFs)?;
    assert_eq!(id, reopened);
    assert_eq!(
        pass(&mut engine, &id, DAY_NOW + 10_000).records_committed,
        0
    );
    assert_eq!(rows(&world.history()?, &id)?, before);
    Ok(())
}

#[test]
fn pruned_queued_directory_drains_with_and_without_reopen() -> TestResult {
    for reopen in [false, true] {
        let world = World::new()?;
        for index in 0..70 {
            world.put(
                &format!("sessions/old-{index:02}/rollout.jsonl"),
                &base_bytes()?,
            )?;
        }
        let fs = ReversedFs::new();
        let (mut engine, id) = world.engine(fs.clone())?;
        drain(&mut engine, &id, DAY_NOW, 8)?;
        let before = rows(&world.history()?, &id)?;
        let report = pass(&mut engine, &id, DAY_NOW + 10_000);
        assert_eq!(report.outcome, PassOutcome::CatchingUp);
        let relative: String = world.history()?.query_row(
            "SELECT relative_path FROM frontier_directories WHERE source_id = ?1 AND relative_path LIKE 'sessions/old-%' ORDER BY relative_path LIMIT 1",
            [&id], |row| row.get(0),
        )?;
        if reopen {
            drop(engine);
            (engine, _) = world.engine(fs)?;
        }
        std::fs::remove_dir_all(world.root.join(&relative))?;
        drain(&mut engine, &id, DAY_NOW + 11_000, 8)?;
        assert_eq!(
            file_state(&world.history()?, &id, &format!("{relative}/rollout.jsonl"))?.2,
            "missing"
        );
        assert_eq!(rows(&world.history()?, &id)?, before);
    }
    Ok(())
}

#[test]
fn opencode_pruned_failed_directory_preserves_history_and_drains() -> TestResult {
    for (reopen, replace_root) in [(false, false), (true, false), (false, true), (true, true)] {
        let world = World::new()?;
        let connection = Connection::open(world.root.join("opencode.db"))?;
        let schema = include_str!("../../../Fixtures/harness/opencode/wal/schema.sql")
            .lines()
            .filter(|line| !line.trim_start().starts_with("PRAGMA"))
            .collect::<Vec<_>>()
            .join("\n");
        connection.execute_batch(&schema)?;
        let cases: Value = serde_json::from_str(include_str!(
            "../../../Fixtures/harness/opencode/peer/cases.json"
        ))?;
        let case = cases
            .as_array()
            .ok_or("peer cases")?
            .iter()
            .find(|case| case["name"] == "named_convention_derives_42")
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
        drop(connection);
        let blocked = world.root.join("queued");
        std::fs::create_dir(&blocked)?;
        let fs = ReversedFs::new();
        let mut engine = Engine::open(&world.data, &world.home);
        let id = engine
            .attach_opencode(fs.clone(), &world.root, enabled(), SourceKind::Custom)
            .map_err(|report| format!("{report:?}"))?;
        drain(&mut engine, &id, DAY_NOW, 4)?;
        let before = engine.observations(&id)?;
        assert_eq!(before.len(), 1);
        *fs.directory_fault.lock().map_err(|_| "fault lock")? = Some(blocked.clone());
        let failed = pass(&mut engine, &id, DAY_NOW + 10_000);
        assert_ne!(failed.outcome, PassOutcome::Consistent);
        assert!(
            count(
                &world.history()?,
                "SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1 AND relative_path = 'queued'",
                &[&id]
            )? > 0
        );
        if reopen {
            drop(engine);
            engine = Engine::open(&world.data, &world.home);
            let restored = engine
                .attach_opencode(fs.clone(), &world.root, enabled(), SourceKind::Custom)
                .map_err(|report| format!("{report:?}"))?;
            assert_eq!(id, restored);
        }
        *fs.directory_fault.lock().map_err(|_| "fault lock")? = None;
        if replace_root {
            let generation = count(
                &world.history()?,
                "SELECT generation FROM sources WHERE source_id = ?1",
                &[&id],
            )?;
            let last_good = count(
                &world.history()?,
                "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
                &[&id],
            )?;
            let root = world.root.clone();
            let moved = world._directory.path().join("moved-root");
            let target = moved.clone();
            fs.inner.on_boundary(move |kind, path| {
                if kind == quotern_core::ingest::fs::OpenKind::Directory && path == blocked {
                    std::fs::rename(&root, &target).expect("move test OpenCode root");
                    std::fs::create_dir(&root).expect("create empty test OpenCode replacement");
                }
            });
            let report = pass(&mut engine, &id, DAY_NOW + 11_000);
            fs.inner.on_boundary(|_, _| {});
            assert_ne!(report.outcome, PassOutcome::Consistent, "{report:?}");
            assert_eq!(report.failure, Some(FailureCode::RootOverlap));
            assert_eq!(report.last_good_ms, Some(last_good));
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT generation FROM sources WHERE source_id = ?1",
                    &[&id]
                )?,
                generation
            );
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
                    &[&id]
                )?,
                last_good
            );
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1 AND relative_path = 'queued'",
                    &[&id]
                )?,
                1
            );
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND file_state = 'missing'",
                    &[&id]
                )?,
                0
            );
            assert_eq!(engine.observations(&id)?, before);
            std::fs::remove_dir(&world.root)?;
            std::fs::rename(moved, &world.root)?;
        } else {
            std::fs::remove_dir(&blocked)?;
        }
        drain(&mut engine, &id, DAY_NOW + 11_000, 4)?;
        assert_eq!(engine.observations(&id)?, before);
        assert_eq!(
            count(
                &world.history()?,
                "SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1",
                &[&id]
            )?,
            0
        );
        let replay = pass(&mut engine, &id, DAY_NOW + 20_000);
        assert_eq!(replay.outcome, PassOutcome::Consistent);
        assert_eq!(engine.observations(&id)?, before);
        assert_eq!(
            count(
                &world.history()?,
                "SELECT COUNT(*) FROM usage_events WHERE source_id = ?1",
                &[&id]
            )?,
            1
        );
    }
    Ok(())
}

#[test]
fn completed_root_disappearance_at_pending_child_never_completes() -> TestResult {
    let world = World::new()?;
    world.put("sessions/old/rollout.jsonl", &base_bytes()?)?;
    let fs = ReversedFs::new();
    let (mut engine, id) = world.engine(fs.clone())?;
    drain(&mut engine, &id, DAY_NOW, 4)?;
    let before = rows(&world.history()?, &id)?;
    let blocked = world.root.join("sessions/old");
    *fs.directory_fault.lock().map_err(|_| "fault lock")? = Some(blocked.clone());
    assert_ne!(
        pass(&mut engine, &id, DAY_NOW + 1000).outcome,
        PassOutcome::Consistent
    );
    assert!(
        count(
            &world.history()?,
            "SELECT COUNT(*) FROM metadata_spool WHERE source_id = ?1 AND relative_path = ''",
            &[&id]
        )? > 0
    );
    *fs.directory_fault.lock().map_err(|_| "fault lock")? = None;
    let root = world.root.clone();
    let moved = world._directory.path().join("moved-root");
    let target = moved.clone();
    fs.inner.on_boundary(move |kind, path| {
        if kind == quotern_core::ingest::fs::OpenKind::Directory && path == blocked {
            std::fs::rename(&root, &target).expect("move test root at child listing boundary");
        }
    });
    let report = pass(&mut engine, &id, DAY_NOW + 2000);
    std::fs::rename(moved, &world.root)?;
    fs.inner.on_boundary(|_, _| {});
    assert_ne!(
        report.outcome,
        PassOutcome::Consistent,
        "completed parent lost: {report:?}"
    );
    assert_eq!(report.failure, Some(FailureCode::SourceChanging));
    assert_eq!(rows(&world.history()?, &id)?, before);
    assert_eq!(
        count(
            &world.history()?,
            "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND file_state = 'missing'",
            &[&id]
        )?,
        0
    );
    drain(&mut engine, &id, DAY_NOW + 3000, 4)?;
    Ok(())
}

#[test]
fn duplicate_lane_changed_stamp_waits_for_corrected_commit() -> TestResult {
    for change in ["correction_append", "append", "replacement"] {
        for reopen in [false, true] {
            let world = World::new()?;
            let relative = "sessions/old/rollout.jsonl";
            let header = "{\"type\":\"session_meta\",\"payload\":{\"id\":\"own\",\"cli_version\":\"0.153.0\"}}\n";
            let record = |response: &str, input: u32| {
                json!({"timestamp": "2026-03-29T08:01:00Z", "type": "token_usage_record",
                    "payload": {"thread_id": "own", "session_id": "own", "response_id": response,
                        "usage": {"input_tokens": input, "total_tokens": input}}})
                .to_string()
                    + "\n"
            };
            let original = format!("{header}{}", record("first", 10));
            let path = world.put(relative, original.as_bytes())?;
            let fs = ReversedFs::new();
            let (mut engine, id) = world.engine(fs.clone())?;
            drain(&mut engine, &id, DAY_NOW, 4)?;
            let before = rows(&world.history()?, &id)?;
            let input = if change == "append" { 10 } else { 20 };
            let corrected = format!("{header}{}{}", record("first", input), record("second", 3));
            let root = world.root.clone();
            let mut changed = false;
            fs.inner.on_boundary(move |kind, opened| {
                if !changed
                    && kind == quotern_core::ingest::fs::OpenKind::Directory
                    && opened == root
                {
                    changed = true;
                    if change == "replacement" {
                        let replacement = path.with_extension("replacement");
                        std::fs::write(&replacement, &corrected).expect("write test replacement");
                        std::fs::rename(replacement, &path).expect("replace test rollout");
                    } else {
                        std::fs::write(&path, &corrected).expect("correct test rollout");
                    }
                }
            });
            let last_good = count(
                &world.history()?,
                "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
                &[&id],
            )?;
            let report = pass(&mut engine, &id, DAY_NOW + 1000);
            fs.inner.on_boundary(|_, _| {});
            assert_eq!(
                report.outcome,
                PassOutcome::CatchingUp,
                "{change}, reopen={reopen}: {report:?}"
            );
            assert_eq!(report.records_committed, 0);
            assert_eq!(rows(&world.history()?, &id)?, before);
            let snapshot = serde_json::to_value(
                engine
                    .today_snapshot("UTC", DAY_NOW + 1000)
                    .map_err(|error| format!("{error:?}"))?,
            )?;
            assert_eq!(snapshot["source_reported"][0]["input"]["value"], 10);
            assert_eq!(
                snapshot["source_reported"][0]["input"]["status"],
                "catching_up"
            );
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
                    &[&id]
                )?,
                last_good
            );
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT dirty FROM sources WHERE source_id = ?1",
                    &[&id]
                )?,
                1
            );
            assert!(
                count(
                    &world.history()?,
                    "SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1",
                    &[&id]
                )? > 0
            );
            if reopen {
                drop(engine);
                (engine, _) = world.engine(fs.clone())?;
            }
            let reports = drain(&mut engine, &id, DAY_NOW + 2000, 4)?;
            assert_eq!(
                reports
                    .iter()
                    .map(|report| report.records_committed)
                    .sum::<u32>(),
                if change == "append" { 1 } else { 2 }
            );
            let after = rows(&world.history()?, &id)?;
            assert_eq!(after.len(), 2);
            assert_eq!(after[0]["input_tokens"], input);
            assert_eq!(after[0]["revision"], if change == "append" { 1 } else { 2 });
            assert_eq!(after[1]["input_tokens"], 3);
            assert_eq!(after[1]["revision"], 1);
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                    &[&id]
                )?,
                if change == "append" { 13 } else { 23 }
            );
            let snapshot = serde_json::to_value(
                engine
                    .today_snapshot("UTC", DAY_NOW + 2000)
                    .map_err(|error| format!("{error:?}"))?,
            )?;
            assert_eq!(
                snapshot["source_reported"][0]["input"]["value"],
                if change == "append" { 13 } else { 23 }
            );
            assert_eq!(snapshot["source_reported"][0]["input"]["status"], "current");
            drop(engine);
            (engine, _) = world.engine(fs)?;
            assert_eq!(pass(&mut engine, &id, DAY_NOW + 5000).records_committed, 0);
            assert_eq!(rows(&world.history()?, &id)?, after);
        }
    }
    Ok(())
}

#[test]
fn replaced_root_at_pending_child_keeps_generation_and_history() -> TestResult {
    for reopen in [false, true] {
        let world = World::new()?;
        world.put("sessions/old/rollout.jsonl", &base_bytes()?)?;
        let fs = ReversedFs::new();
        let (mut engine, id) = world.engine(fs.clone())?;
        drain(&mut engine, &id, DAY_NOW, 4)?;
        let before = rows(&world.history()?, &id)?;
        let blocked = world.root.join("sessions/old");
        *fs.directory_fault.lock().map_err(|_| "fault lock")? = Some(blocked.clone());
        assert_ne!(
            pass(&mut engine, &id, DAY_NOW + 1000).outcome,
            PassOutcome::Consistent
        );
        *fs.directory_fault.lock().map_err(|_| "fault lock")? = None;
        let generation = count(
            &world.history()?,
            "SELECT generation FROM sources WHERE source_id = ?1",
            &[&id],
        )?;
        let last_good = count(
            &world.history()?,
            "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
            &[&id],
        )?;
        let root = world.root.clone();
        let moved = world._directory.path().join("moved-root");
        let target = moved.clone();
        fs.inner.on_boundary(move |kind, path| {
            if kind == quotern_core::ingest::fs::OpenKind::Directory && path == blocked {
                std::fs::rename(&root, &target).expect("move test root");
                std::fs::create_dir(&root).expect("create empty test replacement");
            }
        });
        let report = pass(&mut engine, &id, DAY_NOW + 2000);
        fs.inner.on_boundary(|_, _| {});
        assert_ne!(report.outcome, PassOutcome::Consistent, "{report:?}");
        assert_eq!(report.failure, Some(FailureCode::RootOverlap));
        assert_eq!(report.last_good_ms, Some(last_good));
        assert_eq!(
            count(
                &world.history()?,
                "SELECT generation FROM sources WHERE source_id = ?1",
                &[&id]
            )?,
            generation
        );
        assert_eq!(
            count(
                &world.history()?,
                "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
                &[&id]
            )?,
            last_good
        );
        assert_eq!(
            count(
                &world.history()?,
                "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND file_state = 'missing'",
                &[&id]
            )?,
            0
        );
        assert_eq!(
            count(
                &world.history()?,
                "SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1 AND relative_path = 'sessions/old'",
                &[&id]
            )?,
            1
        );
        assert_eq!(rows(&world.history()?, &id)?, before);
        std::fs::remove_dir(&world.root)?;
        std::fs::rename(moved, &world.root)?;
        if reopen {
            drop(engine);
            (engine, _) = world.engine(fs)?;
        }
        drain(&mut engine, &id, DAY_NOW + 3000, 4)?;
        assert_eq!(rows(&world.history()?, &id)?, before);
        assert_eq!(
            pass(&mut engine, &id, DAY_NOW + 10_000).records_committed,
            0
        );
    }
    Ok(())
}

#[test]
fn replaced_root_at_terminal_listing_never_completes() -> TestResult {
    let world = World::new()?;
    world.basic()?;
    let fs = ReversedFs::new();
    let (mut engine, id) = world.engine(fs.clone())?;
    drain(&mut engine, &id, DAY_NOW, 4)?;
    let before = rows(&world.history()?, &id)?;
    let generation = count(
        &world.history()?,
        "SELECT generation FROM sources WHERE source_id = ?1",
        &[&id],
    )?;
    let last_good = count(
        &world.history()?,
        "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
        &[&id],
    )?;
    let root = world.root.clone();
    let moved = world._directory.path().join("moved-root");
    let target = moved.clone();
    fs.inner.on_boundary(move |kind, path| {
        if kind == quotern_core::ingest::fs::OpenKind::Directory && path == root {
            std::fs::rename(&root, &target).expect("move test root before empty terminal listing");
            std::fs::create_dir(&root).expect("create empty terminal test replacement");
        }
    });
    let physical_before = physical_operations().metadata;
    let report = pass(&mut engine, &id, DAY_NOW + 1000);
    fs.inner.on_boundary(|_, _| {});
    assert_ne!(report.outcome, PassOutcome::Consistent, "{report:?}");
    assert_eq!(report.failure, Some(FailureCode::RootOverlap));
    assert_eq!(report.last_good_ms, Some(last_good));
    assert_eq!(
        physical_operations().metadata - physical_before,
        u64::from(report.counters.stat_calls)
    );
    assert_eq!(
        count(
            &world.history()?,
            "SELECT generation FROM sources WHERE source_id = ?1",
            &[&id]
        )?,
        generation
    );
    assert_eq!(
        count(
            &world.history()?,
            "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
            &[&id]
        )?,
        last_good
    );
    assert_eq!(
        count(
            &world.history()?,
            "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND file_state = 'missing'",
            &[&id]
        )?,
        0
    );
    assert_eq!(rows(&world.history()?, &id)?, before);
    std::fs::remove_dir(&world.root)?;
    std::fs::rename(moved, &world.root)?;
    drop(engine);
    (engine, _) = world.engine(fs)?;
    drain(&mut engine, &id, DAY_NOW + 2000, 4)?;
    assert_eq!(rows(&world.history()?, &id)?, before);
    assert_eq!(pass(&mut engine, &id, DAY_NOW + 5000).records_committed, 0);
    Ok(())
}

#[test]
fn root_replacement_after_committed_file_keeps_last_good() -> TestResult {
    let world = World::new()?;
    world.basic()?;
    let fs = ReversedFs::new();
    let (mut engine, id) = world.engine(fs.clone())?;
    drain(&mut engine, &id, DAY_NOW, 4)?;
    let before = rows(&world.history()?, &id)?;
    let generation = count(
        &world.history()?,
        "SELECT generation FROM sources WHERE source_id = ?1",
        &[&id],
    )?;
    let last_good = count(
        &world.history()?,
        "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
        &[&id],
    )?;
    world.append(BASIC_FILE, appended_record(7).as_bytes())?;
    let root = world.root.clone();
    let moved = world._directory.path().join("moved-root");
    let target = moved.clone();
    fs.inner.on_boundary(move |kind, path| {
        if kind == quotern_core::ingest::fs::OpenKind::Directory && path == root {
            std::fs::rename(&root, &target).expect("move root after valid current commit");
            std::fs::create_dir(&root).expect("create replacement after valid current commit");
        }
    });
    let report = pass(&mut engine, &id, DAY_NOW + 1000);
    fs.inner.on_boundary(|_, _| {});
    assert_eq!(report.records_committed, 1);
    assert_eq!(report.failure, Some(FailureCode::RootOverlap));
    assert_eq!(
        report.last_good_ms,
        Some(last_good),
        "root mismatch must not advance freshness after a valid file commit: {report:?}"
    );
    assert_eq!(
        count(
            &world.history()?,
            "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
            &[&id]
        )?,
        last_good
    );
    assert_eq!(
        count(
            &world.history()?,
            "SELECT generation FROM sources WHERE source_id = ?1",
            &[&id]
        )?,
        generation
    );
    assert_eq!(
        count(
            &world.history()?,
            "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND file_state = 'missing'",
            &[&id]
        )?,
        0
    );
    let after = rows(&world.history()?, &id)?;
    assert_eq!(after.len(), 4);
    assert!(before.iter().all(|row| after.contains(row)));
    assert_eq!(
        after
            .iter()
            .filter(|row| row["response_id"] == "resp_live_7")
            .count(),
        1
    );
    std::fs::remove_dir(&world.root)?;
    std::fs::rename(moved, &world.root)?;
    drop(engine);
    (engine, _) = world.engine(fs)?;
    drain(&mut engine, &id, DAY_NOW + 2000, 4)?;
    assert_eq!(rows(&world.history()?, &id)?, after);
    assert_eq!(pass(&mut engine, &id, DAY_NOW + 5000).records_committed, 0);
    Ok(())
}

#[test]
fn terminal_root_and_data_identity_budget_preserves_generation() -> TestResult {
    for data_identity in [false, true] {
        let world = World::new()?;
        world.basic()?;
        let fs = ReversedFs::new();
        let (mut engine, id) = world.engine(fs.clone())?;
        drain(&mut engine, &id, DAY_NOW, 4)?;
        let before = rows(&world.history()?, &id)?;
        let generation = count(
            &world.history()?,
            "SELECT generation FROM sources WHERE source_id = ?1",
            &[&id],
        )?;
        let last_good = count(
            &world.history()?,
            "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
            &[&id],
        )?;
        let root = world.root.clone();
        let target = if data_identity {
            world.data.clone()
        } else {
            root.clone()
        };
        let budget = Arc::clone(&fs.metadata_budget);
        fs.inner.on_boundary(move |kind, path| {
            if kind == quotern_core::ingest::fs::OpenKind::Directory && path == root {
                *budget.lock().expect("arm terminal metadata budget") = Some(target.clone());
            }
        });
        let physical_before = physical_operations().metadata;
        let report = pass(&mut engine, &id, DAY_NOW + 1000);
        fs.inner.on_boundary(|_, _| {});
        assert_eq!(report.counters.stat_calls, 40_000);
        assert_eq!(physical_operations().metadata - physical_before, 40_000);
        assert_eq!(
            report.outcome,
            PassOutcome::CatchingUp,
            "data_identity={data_identity}: {report:?}"
        );
        assert_eq!(report.last_good_ms, Some(last_good));
        assert_eq!(report.records_committed, 0);
        assert_eq!(
            count(
                &world.history()?,
                "SELECT generation FROM sources WHERE source_id = ?1",
                &[&id]
            )?,
            generation
        );
        assert_eq!(
            count(
                &world.history()?,
                "SELECT dirty FROM sources WHERE source_id = ?1",
                &[&id]
            )?,
            1
        );
        assert_eq!(
            count(
                &world.history()?,
                "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND file_state = 'missing'",
                &[&id]
            )?,
            0
        );
        assert_eq!(rows(&world.history()?, &id)?, before);
        drop(engine);
        *fs.metadata_budget.lock().map_err(|_| "budget lock")? = None;
        (engine, _) = world.engine(fs)?;
        let reports = drain(&mut engine, &id, DAY_NOW + 2000, 4)?;
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].records_committed, 0);
        assert_eq!(
            count(
                &world.history()?,
                "SELECT generation FROM sources WHERE source_id = ?1",
                &[&id]
            )?,
            generation + 1
        );
        assert_eq!(rows(&world.history()?, &id)?, before);
        assert_eq!(pass(&mut engine, &id, DAY_NOW + 5000).records_committed, 0);
    }
    Ok(())
}

#[test]
fn opencode_root_replacement_after_publication_keeps_last_good() -> TestResult {
    let world = World::new()?;
    let path = world.root.join("opencode.db");
    let connection = Connection::open(&path)?;
    let schema = include_str!("../../../Fixtures/harness/opencode/wal/schema.sql")
        .lines()
        .filter(|line| !line.trim_start().starts_with("PRAGMA"))
        .collect::<Vec<_>>()
        .join("\n");
    connection.execute_batch(&schema)?;
    let cases: Value = serde_json::from_str(include_str!(
        "../../../Fixtures/harness/opencode/peer/cases.json"
    ))?;
    let case = cases
        .as_array()
        .ok_or("peer cases")?
        .iter()
        .find(|case| case["name"] == "named_convention_derives_42")
        .ok_or("peer case")?;
    connection.execute(
        "INSERT INTO message(id, session_id, time_created, data) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![
            case["message_id"].as_str().ok_or("message")?,
            case["session_id"].as_str().ok_or("session")?,
            case["time_created"].as_i64().ok_or("time")?,
            serde_json::to_vec(&case["data"])?
        ],
    )?;
    drop(connection);
    let fs = ReversedFs::new();
    let mut engine = Engine::open(&world.data, &world.home);
    let id = engine
        .attach_opencode(fs.clone(), &world.root, enabled(), SourceKind::Custom)
        .map_err(|report| format!("{report:?}"))?;
    drain(&mut engine, &id, DAY_NOW, 4)?;
    let before = engine.observations(&id)?;
    assert_eq!(before.len(), 1);
    let generation = count(
        &world.history()?,
        "SELECT generation FROM sources WHERE source_id = ?1",
        &[&id],
    )?;
    let last_good = count(
        &world.history()?,
        "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
        &[&id],
    )?;
    let connection = Connection::open(&path)?;
    connection.execute(
        "INSERT INTO message(id, session_id, time_created, data) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![
            "msg_new",
            case["session_id"].as_str().ok_or("session")?,
            case["time_created"].as_i64().ok_or("time")?,
            serde_json::to_vec(&case["data"])?
        ],
    )?;
    drop(connection);
    let root = world.root.clone();
    let moved = world._directory.path().join("moved-root");
    let target = moved.clone();
    fs.inner.on_boundary(move |kind, path| {
        if kind == quotern_core::ingest::fs::OpenKind::Directory && path == root {
            std::fs::rename(&root, &target).expect("move OpenCode root after valid acquisition");
            std::fs::create_dir(&root).expect("create replacement OpenCode root");
        }
    });
    let report = pass(&mut engine, &id, DAY_NOW + 1000);
    fs.inner.on_boundary(|_, _| {});
    assert_eq!(report.outcome, PassOutcome::Partial, "{report:?}");
    assert_eq!(report.failure, Some(FailureCode::RootOverlap));
    assert_eq!(report.records_committed, 2);
    assert_eq!(report.last_good_ms, Some(last_good));
    assert_eq!(
        count(
            &world.history()?,
            "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
            &[&id]
        )?,
        last_good
    );
    assert_eq!(
        count(
            &world.history()?,
            "SELECT generation FROM sources WHERE source_id = ?1",
            &[&id]
        )?,
        generation
    );
    assert_eq!(
        count(
            &world.history()?,
            "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND file_state = 'missing'",
            &[&id]
        )?,
        0
    );
    let after = engine.observations(&id)?;
    assert_eq!(after.len(), 2);
    assert!(before.iter().all(|row| after.contains(row)));
    std::fs::remove_dir(&world.root)?;
    std::fs::rename(moved, &world.root)?;
    drop(engine);
    engine = Engine::open(&world.data, &world.home);
    let reopened = engine
        .attach_opencode(fs, &world.root, enabled(), SourceKind::Custom)
        .map_err(|report| format!("{report:?}"))?;
    assert_eq!(id, reopened);
    drain(&mut engine, &id, DAY_NOW + 2000, 4)?;
    assert_eq!(engine.observations(&id)?, after);
    assert_eq!(
        count(
            &world.history()?,
            "SELECT COUNT(*) FROM usage_events WHERE source_id = ?1",
            &[&id]
        )?,
        2
    );
    Ok(())
}

#[test]
fn missing_listing_confirmation_budget_keeps_durable_work() -> TestResult {
    let world = World::new()?;
    world.put("sessions/old/rollout.jsonl", &base_bytes()?)?;
    let fs = ReversedFs::new();
    let (mut engine, id) = world.engine(fs.clone())?;
    drain(&mut engine, &id, DAY_NOW, 4)?;
    let before = rows(&world.history()?, &id)?;
    let blocked = world.root.join("sessions/old");
    *fs.directory_fault.lock().map_err(|_| "fault lock")? = Some(blocked.clone());
    assert_ne!(
        pass(&mut engine, &id, DAY_NOW + 1000).outcome,
        PassOutcome::Consistent
    );
    *fs.directory_fault.lock().map_err(|_| "fault lock")? = None;
    world.put("sessions/old/rollout-new.jsonl", &base_bytes()?)?;
    let new_record = appended_record(7).replace(
        "0195f000-0000-7000-8000-00000000b001",
        "0195f000-0000-7000-8000-00000000c001",
    );
    world.append("sessions/old/rollout-new.jsonl", new_record.as_bytes())?;
    let generation = count(
        &world.history()?,
        "SELECT generation FROM sources WHERE source_id = ?1",
        &[&id],
    )?;
    let last_good = count(
        &world.history()?,
        "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
        &[&id],
    )?;
    *fs.confirmation_budget.lock().map_err(|_| "fault lock")? = Some(blocked);
    let physical_before = physical_operations().metadata;
    let report = pass(&mut engine, &id, DAY_NOW + 2000);
    assert_eq!(report.counters.stat_calls, 40_000);
    assert_eq!(physical_operations().metadata - physical_before, 40_000);
    assert_eq!(report.outcome, PassOutcome::CatchingUp, "{report:?}");
    assert_eq!(report.records_committed, 0);
    assert_eq!(
        count(
            &world.history()?,
            "SELECT dirty FROM sources WHERE source_id = ?1",
            &[&id]
        )?,
        1
    );
    assert_eq!(
        count(
            &world.history()?,
            "SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1 AND relative_path = 'sessions/old'",
            &[&id]
        )?,
        1
    );
    assert_eq!(
        count(
            &world.history()?,
            "SELECT generation FROM sources WHERE source_id = ?1",
            &[&id]
        )?,
        generation
    );
    assert_eq!(
        count(
            &world.history()?,
            "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
            &[&id]
        )?,
        last_good
    );
    assert_eq!(
        count(
            &world.history()?,
            "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND file_state = 'missing'",
            &[&id]
        )?,
        0
    );
    assert_eq!(rows(&world.history()?, &id)?, before);
    drop(engine);
    *fs.confirmation_budget.lock().map_err(|_| "fault lock")? = None;
    let (mut engine, reopened) = world.engine(fs)?;
    assert_eq!(id, reopened);
    let reports = drain(&mut engine, &id, DAY_NOW + 3000, 4)?;
    assert_eq!(
        reports
            .iter()
            .map(|report| report.records_committed)
            .sum::<u32>(),
        1
    );
    let after = rows(&world.history()?, &id)?;
    assert_eq!(after.len(), 3);
    assert_eq!(
        count(
            &world.history()?,
            "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
            &[&id]
        )?,
        31
    );
    let snapshot = serde_json::to_value(
        engine
            .today_snapshot("UTC", DAY_NOW + 3000)
            .map_err(|error| format!("{error:?}"))?,
    )?;
    assert_eq!(snapshot["source_reported"][0]["input"]["value"], 31);
    assert_eq!(
        after
            .iter()
            .filter(|row| row["response_id"] == "resp_live_7")
            .count(),
        1
    );
    assert_eq!(
        pass(&mut engine, &id, DAY_NOW + 10_000).records_committed,
        0
    );
    assert_eq!(rows(&world.history()?, &id)?, after);
    Ok(())
}

fn refused_root_completion_rediscovers_present_removed_and_unseen_files(codex: bool) -> TestResult {
    for (reopen, pending_child) in [(false, false), (true, false), (false, true), (true, true)] {
        let world = World::new()?;
        let present = reported_path(codex, "present");
        let removed = reported_path(codex, "removed");
        let unseen = reported_path(codex, "unseen");
        world.put(&present, &reported_bytes(codex, "present", "present", 10))?;
        world.put(&removed, &reported_bytes(codex, "removed", "removed", 20))?;
        let blocked = world
            .root
            .join(if codex { "sessions/blocked" } else { "queued" });
        std::fs::create_dir_all(&blocked)?;
        let fs = ReversedFs::new();
        let (mut engine, id) = reported_engine(&world, fs.clone(), codex)?;
        drain(&mut engine, &id, DAY_NOW, 4)?;
        let before = rows(&world.history()?, &id)?;
        assert_eq!(before.len(), 2);
        if pending_child {
            *fs.directory_fault.lock().map_err(|_| "fault lock")? = Some(blocked.clone());
            assert_ne!(
                pass(&mut engine, &id, DAY_NOW + 500).outcome,
                PassOutcome::Consistent
            );
            *fs.directory_fault.lock().map_err(|_| "fault lock")? = None;
        }
        let generation = count(
            &world.history()?,
            "SELECT generation FROM sources WHERE source_id = ?1",
            &[&id],
        )?;
        let last_good = count(
            &world.history()?,
            "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
            &[&id],
        )?;
        std::fs::remove_file(world.root.join(&removed))?;
        world.put(&unseen, &reported_bytes(codex, "unseen", "unseen", 7))?;
        let root = world.root.clone();
        let moved = world._directory.path().join("registered-root");
        let saved = moved.clone();
        let switch = if pending_child {
            blocked.clone()
        } else {
            root.clone()
        };
        fs.inner.on_boundary(move |kind, path| {
            if kind == quotern_core::ingest::fs::OpenKind::Directory && path == switch {
                std::fs::rename(&root, &saved).expect("move registered fixture root");
                std::fs::create_dir(&root).expect("create substitute root");
            }
        });
        let report = pass(&mut engine, &id, DAY_NOW + 1000);
        fs.inner.on_boundary(|_, _| {});
        assert_eq!(
            report.failure,
            Some(FailureCode::RootOverlap),
            "codex={codex}: {report:?}"
        );
        assert_last_good(&world, &engine, &id, &report, last_good)?;
        assert_eq!(rows(&world.history()?, &id)?, before);
        assert_eq!(
            count(
                &world.history()?,
                "SELECT generation FROM sources WHERE source_id = ?1",
                &[&id]
            )?,
            generation
        );
        assert_eq!(
            count(
                &world.history()?,
                "SELECT COUNT(*) FROM metadata_spool WHERE source_id = ?1 AND parser_kind = 'directory'",
                &[&id]
            )?,
            0,
            "refused directory completions must not survive"
        );
        assert!(
            count(
                &world.history()?,
                "SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1 AND relative_path = ''",
                &[&id]
            )? > 0
        );
        if pending_child {
            let pending = blocked
                .strip_prefix(&world.root)?
                .to_str()
                .ok_or("pending path")?;
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1 AND relative_path = ?2",
                    &[&id, &pending]
                )?,
                1,
                "prior pending directory retained"
            );
        }
        std::fs::remove_dir(&world.root)?;
        std::fs::rename(moved, &world.root)?;
        if reopen {
            drop(engine);
            (engine, _) = reported_engine(&world, fs.clone(), codex)?;
        }
        let reports = drain(&mut engine, &id, DAY_NOW + 2000, 6)?;
        assert!(reports.iter().any(|report| report.records_committed > 0));
        let mut expected = vec![
            (present, "present".to_owned()),
            (removed, "missing".to_owned()),
            (unseen, "present".to_owned()),
        ];
        expected.sort();
        assert_eq!(
            source_membership(&world.history()?, &id)?,
            expected,
            "codex={codex}, reopen={reopen}"
        );
        let after = rows(&world.history()?, &id)?;
        assert_eq!(after.len(), 3);
        assert!(before.iter().all(|row| after.contains(row)));
        assert_eq!(
            count(
                &world.history()?,
                "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                &[&id]
            )?,
            37
        );
        assert_eq!(
            count(
                &world.history()?,
                "SELECT generation FROM sources WHERE source_id = ?1",
                &[&id]
            )?,
            generation + 1
        );
        assert_eq!(
            count(
                &world.history()?,
                "SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1",
                &[&id]
            )?,
            0
        );
        assert_eq!(
            pass(&mut engine, &id, DAY_NOW + 10_000).records_committed,
            if codex { 0 } else { 2 }
        );
        assert_eq!(rows(&world.history()?, &id)?, after);
    }
    Ok(())
}

#[test]
fn codex_refused_root_completion_rediscovers_present_removed_and_unseen_files() -> TestResult {
    refused_root_completion_rediscovers_present_removed_and_unseen_files(true)
}

#[test]
fn opencode_refused_root_completion_rediscovers_present_removed_and_unseen_files() -> TestResult {
    refused_root_completion_rediscovers_present_removed_and_unseen_files(false)
}

fn populated_root_replacement_refuses_foreign_batch_after_valid_file(codex: bool) -> TestResult {
    for boundary in if codex {
        vec![
            "after_commit",
            "before_open",
            "during_read",
            "before_commit",
        ]
    } else {
        vec!["before_open"]
    } {
        for reopen in [false, true] {
            let world = World::new()?;
            let first = reported_path(codex, "first");
            let second = reported_path(codex, "second");
            world.put(&first, &reported_bytes(codex, "first", "first", 10))?;
            world.put(&second, &reported_bytes(codex, "second", "second", 20))?;
            let fs = ReversedFs::new();
            let (mut engine, id) = reported_engine(&world, fs.clone(), codex)?;
            drain(&mut engine, &id, DAY_NOW, 4)?;
            let before = rows(&world.history()?, &id)?;
            let old_second = file_state(&world.history()?, &id, &second)?;
            let generation = count(
                &world.history()?,
                "SELECT generation FROM sources WHERE source_id = ?1",
                &[&id],
            )?;
            let last_good = count(
                &world.history()?,
                "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
                &[&id],
            )?;
            world.put(&first, &reported_bytes(codex, "first", "first", 11))?;
            world.put(&second, &reported_bytes(codex, "second", "second", 21))?;
            // Known-path ordering is explicit, independent of filesystem timestamp precision.
            world.history()?.execute("UPDATE source_files SET visit_seq = CASE WHEN relative_path = ?2 THEN 0 ELSE 1 END WHERE source_id = ?1", rusqlite::params![id, first])?;
            let root = world.root.clone();
            let moved = world._directory.path().join("registered-root");
            let substitute = world._directory.path().join("substitute-root");
            let foreign = substitute.join(&second);
            std::fs::create_dir_all(foreign.parent().ok_or("foreign parent")?)?;
            let mut foreign_bytes = reported_bytes(codex, "second", "second", 900);
            if codex {
                let additional = reported_bytes(codex, "second", "foreign", 800);
                foreign_bytes.extend_from_slice(
                    &additional[additional
                        .iter()
                        .position(|byte| *byte == b'\n')
                        .ok_or("foreign header")?
                        + 1..],
                );
            } else {
                std::fs::write(
                    substitute.join(reported_path(false, "foreign")),
                    reported_bytes(false, "foreign", "foreign", 800),
                )?;
            }
            std::fs::write(&foreign, foreign_bytes)?;
            let saved = moved.clone();
            if boundary == "before_commit" {
                let mut lines = 0;
                quotern_core::adapters::codex::set_line_hook(Some(Box::new(move || {
                    lines += 1;
                    if lines == 3 {
                        std::fs::rename(&root, &saved).expect("move root between read and commit");
                        std::fs::rename(&substitute, &root).expect("install populated substitute");
                    }
                })));
            } else if boundary != "after_commit" {
                let target = world.root.join(&second);
                fs.inner.on_boundary(move |kind, path| {
                    if kind
                        == if codex && boundary == "during_read" {
                            quotern_core::ingest::fs::OpenKind::TailRead
                        } else if codex {
                            quotern_core::ingest::fs::OpenKind::Tail
                        } else {
                            quotern_core::ingest::fs::OpenKind::Bounded
                        }
                        && path == target
                    {
                        std::fs::rename(&root, &saved).expect("move root at acquisition");
                        std::fs::rename(&substitute, &root).expect("install populated substitute");
                    }
                });
            } else {
                let mut switched = false;
                quotern_core::adapters::codex::set_file_commit_hook(Some(Box::new(move || {
                    if !switched {
                        switched = true;
                        std::fs::rename(&root, &saved).expect("move root after valid publication");
                        std::fs::rename(&substitute, &root).expect("install populated substitute");
                    }
                })));
            }
            let report = pass(&mut engine, &id, DAY_NOW + 1000);
            fs.inner.on_boundary(|_, _| {});
            quotern_core::adapters::codex::set_file_commit_hook(None);
            quotern_core::adapters::codex::set_line_hook(None);
            assert_eq!(
                report.failure,
                Some(FailureCode::RootOverlap),
                "boundary={boundary}: {report:?}"
            );
            assert_eq!(report.records_committed, 1);
            assert_last_good(&world, &engine, &id, &report, last_good)?;
            let after = rows(&world.history()?, &id)?;
            assert_eq!(after.len(), 2, "no foreign response may publish");
            assert_eq!(
                after
                    .iter()
                    .find(|row| row["response_id"] == "first")
                    .ok_or("first")?["input_tokens"],
                11
            );
            assert!(
                after.contains(
                    before
                        .iter()
                        .find(|row| row["response_id"] == "second")
                        .ok_or("second")?
                )
            );
            assert_eq!(file_state(&world.history()?, &id, &second)?, old_second);
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT COUNT(*) FROM metadata_spool WHERE source_id = ?1",
                    &[&id]
                )?,
                0,
                "refused presence witnesses cannot survive"
            );
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                    &[&id]
                )?,
                31
            );
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT generation FROM sources WHERE source_id = ?1",
                    &[&id]
                )?,
                generation
            );
            std::fs::rename(&world.root, world._directory.path().join("rejected-root"))?;
            std::fs::rename(moved, &world.root)?;
            if reopen {
                drop(engine);
                (engine, _) = reported_engine(&world, fs.clone(), codex)?;
            }
            drain(&mut engine, &id, DAY_NOW + 2000, 6)?;
            let recovered = rows(&world.history()?, &id)?;
            assert_eq!(recovered.len(), 2);
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                    &[&id]
                )?,
                32
            );
            assert!(recovered.iter().all(|row| row["revision"] == 2));
            let replay = pass(&mut engine, &id, DAY_NOW + 10_000);
            if codex {
                assert_eq!(replay.records_committed, 0);
            }
            assert_eq!(rows(&world.history()?, &id)?, recovered);
        }
    }
    Ok(())
}

#[test]
fn codex_populated_root_replacement_refuses_foreign_batch_after_valid_file() -> TestResult {
    populated_root_replacement_refuses_foreign_batch_after_valid_file(true)
}

#[test]
fn opencode_populated_root_replacement_refuses_foreign_batch_after_valid_file() -> TestResult {
    populated_root_replacement_refuses_foreign_batch_after_valid_file(false)
}

fn late_identity_budget_preserves_freshness_after_positive_publication(codex: bool) -> TestResult {
    for (data_identity, reopen) in [(false, false), (false, true), (true, false), (true, true)] {
        let world = World::new()?;
        let relative = reported_path(codex, "present");
        world.put(&relative, &reported_bytes(codex, "own", "present", 10))?;
        let fs = ReversedFs::new();
        let (mut engine, id) = reported_engine(&world, fs.clone(), codex)?;
        drain(&mut engine, &id, DAY_NOW, 4)?;
        let generation = count(
            &world.history()?,
            "SELECT generation FROM sources WHERE source_id = ?1",
            &[&id],
        )?;
        let last_good = count(
            &world.history()?,
            "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
            &[&id],
        )?;
        world.put(&relative, &reported_bytes(codex, "own", "present", 11))?;
        let root = world.root.clone();
        let target = if data_identity {
            world.data.clone()
        } else {
            root.clone()
        };
        let budget = Arc::clone(&fs.metadata_budget);
        fs.inner.on_boundary(move |kind, path| {
            if kind == quotern_core::ingest::fs::OpenKind::Directory && path == root {
                *budget.lock().expect("arm late identity budget") = Some(target.clone());
            }
        });
        let physical_before = physical_operations().metadata;
        let report = pass(&mut engine, &id, DAY_NOW + 1000);
        fs.inner.on_boundary(|_, _| {});
        assert_eq!(
            report.outcome,
            PassOutcome::CatchingUp,
            "codex={codex}, data={data_identity}: {report:?}"
        );
        assert_eq!(report.counters.stat_calls, 40_000);
        assert_eq!(physical_operations().metadata - physical_before, 40_000);
        assert!(
            report.records_committed > 0,
            "positive publication discriminator: {report:?}"
        );
        assert_last_good(&world, &engine, &id, &report, last_good)?;
        assert_eq!(
            count(
                &world.history()?,
                "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                &[&id]
            )?,
            11
        );
        assert_eq!(
            count(
                &world.history()?,
                "SELECT generation FROM sources WHERE source_id = ?1",
                &[&id]
            )?,
            generation
        );
        assert_eq!(
            count(
                &world.history()?,
                "SELECT dirty FROM sources WHERE source_id = ?1",
                &[&id]
            )?,
            1
        );
        let snapshot = serde_json::to_value(
            engine
                .today_snapshot("UTC", DAY_NOW + 2000)
                .map_err(|error| format!("{error:?}"))?,
        )?;
        assert_eq!(
            snapshot["source_reported"][0]["input"]["status"],
            "catching_up"
        );
        assert_eq!(
            count(
                &world.history()?,
                "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND file_state = 'missing'",
                &[&id]
            )?,
            0
        );
        let after = rows(&world.history()?, &id)?;
        *fs.metadata_budget.lock().map_err(|_| "budget lock")? = None;
        if reopen {
            drop(engine);
            (engine, _) = reported_engine(&world, fs.clone(), codex)?;
        }
        assert_last_good(&world, &engine, &id, &report, last_good)?;
        assert_eq!(rows(&world.history()?, &id)?, after);
        drain(&mut engine, &id, DAY_NOW + 2000, 6)?;
        assert_eq!(
            count(
                &world.history()?,
                "SELECT generation FROM sources WHERE source_id = ?1",
                &[&id]
            )?,
            generation + 1
        );
        assert_eq!(rows(&world.history()?, &id)?, after);
    }
    Ok(())
}

#[test]
fn codex_late_identity_budget_preserves_freshness_after_positive_publication() -> TestResult {
    late_identity_budget_preserves_freshness_after_positive_publication(true)
}

#[test]
fn opencode_late_identity_budget_preserves_freshness_after_positive_publication() -> TestResult {
    late_identity_budget_preserves_freshness_after_positive_publication(false)
}

#[test]
fn data_directory_replacement_at_terminal_boundary_is_refused() -> TestResult {
    for codex in [true, false] {
        let world = World::new()?;
        let relative = reported_path(codex, "present");
        world.put(&relative, &reported_bytes(codex, "own", "present", 10))?;
        let fs = ReversedFs::new();
        let (mut engine, id) = reported_engine(&world, fs.clone(), codex)?;
        drain(&mut engine, &id, DAY_NOW, 4)?;
        let before = rows(&world.history()?, &id)?;
        let generation = count(
            &world.history()?,
            "SELECT generation FROM sources WHERE source_id = ?1",
            &[&id],
        )?;
        let last_good = count(
            &world.history()?,
            "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
            &[&id],
        )?;
        let root = world.root.clone();
        let data = world.data.clone();
        let moved = world._directory.path().join("owned-data");
        let saved = moved.clone();
        fs.inner.on_boundary(move |kind, path| {
            if kind == quotern_core::ingest::fs::OpenKind::Directory && path == root {
                std::fs::rename(&data, &saved).expect("move owned data at terminal boundary");
                std::fs::create_dir(&data).expect("create substitute data");
                std::fs::write(data.join("sentinel"), b"substitute unchanged")
                    .expect("write substitute sentinel");
            }
        });
        let report = pass(&mut engine, &id, DAY_NOW + 1000);
        fs.inner.on_boundary(|_, _| {});
        assert_ne!(
            report.outcome,
            PassOutcome::Consistent,
            "codex={codex}: {report:?}"
        );
        assert!(
            matches!(
                report.failure,
                Some(FailureCode::RootOverlap | FailureCode::Store)
            ),
            "{report:?}"
        );
        assert_eq!(report.last_good_ms, Some(last_good));
        assert_eq!(
            std::fs::read(world.data.join("sentinel"))?,
            b"substitute unchanged"
        );
        assert_eq!(
            std::fs::read_dir(&world.data)?.count(),
            1,
            "no writes beneath substitute data directory"
        );
        std::fs::rename(&world.data, world._directory.path().join("rejected-data"))?;
        std::fs::rename(moved, &world.data)?;
        assert_eq!(rows(&world.history()?, &id)?, before);
        assert_eq!(
            count(
                &world.history()?,
                "SELECT generation FROM sources WHERE source_id = ?1",
                &[&id]
            )?,
            generation
        );
        assert_eq!(
            count(
                &world.history()?,
                "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
                &[&id]
            )?,
            last_good
        );
        assert_eq!(
            count(
                &world.history()?,
                "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND file_state = 'missing'",
                &[&id]
            )?,
            0
        );
        drop(engine);
        (engine, _) = reported_engine(&world, fs, codex)?;
        drain(&mut engine, &id, DAY_NOW + 2000, 6)?;
        assert_eq!(rows(&world.history()?, &id)?, before);
    }
    Ok(())
}

#[test]
fn data_directory_replacement_during_file_acquisition_retains_owned_history() -> TestResult {
    for codex in [true, false] {
        for during_read in [false, true] {
            for reopen in [false, true] {
                let world = World::new()?;
                let first = reported_path(codex, "first");
                let second = reported_path(codex, "second");
                world.put(&first, &reported_bytes(codex, "first", "first", 10))?;
                world.put(&second, &reported_bytes(codex, "second", "second", 20))?;
                let fs = ReversedFs::new();
                let (mut engine, id) = reported_engine(&world, fs.clone(), codex)?;
                drain(&mut engine, &id, DAY_NOW, 4)?;
                let old_second = file_state(&world.history()?, &id, &second)?;
                let generation = count(
                    &world.history()?,
                    "SELECT generation FROM sources WHERE source_id = ?1",
                    &[&id],
                )?;
                let last_good = count(
                    &world.history()?,
                    "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
                    &[&id],
                )?;
                world.put(&first, &reported_bytes(codex, "first", "first", 11))?;
                world.put(&second, &reported_bytes(codex, "second", "second", 21))?;
                world.history()?.execute("UPDATE source_files SET visit_seq = CASE WHEN relative_path = ?2 THEN 0 ELSE 1 END WHERE source_id = ?1", rusqlite::params![id, first])?;
                let target = world.root.join(&second);
                let data = world.data.clone();
                let moved = world._directory.path().join("owned-data");
                let saved = moved.clone();
                if !codex && during_read {
                    *fs.bounded_swap.lock().map_err(|_| "swap lock")? = Some(DataSwap {
                        target: target.clone(),
                        data: data.clone(),
                        saved: saved.clone(),
                    });
                }
                fs.inner.on_boundary(move |kind, path| {
                    if path == target
                        && (codex || !during_read)
                        && kind
                            == if codex && during_read {
                                quotern_core::ingest::fs::OpenKind::TailRead
                            } else if codex {
                                quotern_core::ingest::fs::OpenKind::Tail
                            } else {
                                quotern_core::ingest::fs::OpenKind::Bounded
                            }
                    {
                        std::fs::rename(&data, &saved).expect("move owned data at acquisition");
                        std::fs::create_dir(&data).expect("install substitute data");
                        std::fs::write(data.join("sentinel"), b"substitute unchanged")
                            .expect("write substitute sentinel");
                    }
                });
                let report = pass(&mut engine, &id, DAY_NOW + 1000);
                fs.inner.on_boundary(|_, _| {});
                if !codex && during_read {
                    assert!(
                        fs.bounded_swap.lock().map_err(|_| "swap lock")?.is_none(),
                        "post-acquisition injection completed"
                    );
                    let trace = fs.bounded_acquisitions.lock().map_err(|_| "trace lock")?;
                    assert_eq!(trace.len(), 1);
                    assert!(
                        trace[0].1 > trace[0].0 && trace[0].2 > 0,
                        "acquisition-before-swap discriminator"
                    );
                }
                assert!(
                    matches!(
                        report.failure,
                        Some(FailureCode::RootOverlap | FailureCode::Store)
                    ),
                    "{report:?}"
                );
                assert_ne!(report.outcome, PassOutcome::Consistent);
                assert_eq!(report.last_good_ms, Some(last_good));
                assert_eq!(
                    std::fs::read(world.data.join("sentinel"))?,
                    b"substitute unchanged"
                );
                assert_eq!(
                    std::fs::read_dir(&world.data)?.count(),
                    1,
                    "no substitute writes"
                );
                std::fs::rename(&world.data, world._directory.path().join("rejected-data"))?;
                std::fs::rename(moved, &world.data)?;
                assert_eq!(file_state(&world.history()?, &id, &second)?, old_second);
                assert_eq!(
                    count(
                        &world.history()?,
                        "SELECT generation FROM sources WHERE source_id = ?1",
                        &[&id]
                    )?,
                    generation
                );
                assert_eq!(
                    count(
                        &world.history()?,
                        "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
                        &[&id]
                    )?,
                    last_good
                );
                assert_eq!(
                    count(
                        &world.history()?,
                        "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND file_state = 'missing'",
                        &[&id]
                    )?,
                    0
                );
                assert_eq!(
                    count(
                        &world.history()?,
                        "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                        &[&id]
                    )?,
                    if codex { 31 } else { 30 }
                );
                if reopen {
                    drop(engine);
                    (engine, _) = reported_engine(&world, fs.clone(), codex)?;
                }
                drain(&mut engine, &id, DAY_NOW + 2000, 6)?;
                let recovered = rows(&world.history()?, &id)?;
                assert_eq!(recovered.len(), 2);
                assert_eq!(
                    count(
                        &world.history()?,
                        "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                        &[&id]
                    )?,
                    32
                );
                assert!(recovered.iter().all(|row| row["revision"] == 2));
                pass(&mut engine, &id, DAY_NOW + 10_000);
                assert_eq!(rows(&world.history()?, &id)?, recovered);
            }
        }
    }
    Ok(())
}

#[test]
fn failed_equal_stamp_acquisition_retains_frontier_until_next_pass() -> TestResult {
    for unstable in [false, true] {
        for reopen in [false, true] {
            let world = World::new()?;
            let relative = reported_path(true, "present");
            let path = world.put(&relative, &reported_bytes(true, "own", "present", 10))?;
            let fs = ReversedFs::new();
            let (mut engine, id) = world.engine(fs.clone())?;
            drain(&mut engine, &id, DAY_NOW, 4)?;
            let before = rows(&world.history()?, &id)?;
            let old_state = file_state(&world.history()?, &id, &relative)?;
            let generation = count(
                &world.history()?,
                "SELECT generation FROM sources WHERE source_id = ?1",
                &[&id],
            )?;
            let selected = reported_bytes(true, "own", "present", 20);
            std::fs::write(&path, &selected)?;
            let selected_stamp = independent_stamp(&path)?;
            let modified = std::fs::metadata(&path)?.modified()?;
            let root = world.root.clone();
            let target = path.clone();
            let parked = path.with_extension("parked");
            let mut changed = false;
            fs.inner.on_boundary(move |kind, opened| {
                use quotern_core::ingest::fs::OpenKind;
                if !changed
                    && opened == target
                    && kind
                        == if unstable {
                            OpenKind::TailRead
                        } else {
                            OpenKind::Tail
                        }
                {
                    changed = true;
                    if unstable {
                        std::fs::OpenOptions::new()
                            .append(true)
                            .open(&target)
                            .expect("open unstable fixture")
                            .write_all(b" ")
                            .expect("change fixture while read");
                    } else {
                        std::fs::rename(&target, &parked)
                            .expect("temporarily unavailable acquisition");
                    }
                }
                if changed && kind == OpenKind::Directory && opened == root {
                    if unstable {
                        std::fs::write(&target, &selected)
                            .expect("restore selected bytes before later lane");
                        std::fs::File::open(&target)
                            .expect("restored file")
                            .set_modified(modified)
                            .expect("restore selected timestamp");
                    } else {
                        std::fs::rename(&parked, &target)
                            .expect("restore same file before later lane");
                    }
                }
            });
            let acquisitions = fs.inner.metrics().tail_reads;
            let report = pass(&mut engine, &id, DAY_NOW + 1000);
            fs.inner.on_boundary(|_, _| {});
            assert_eq!(independent_stamp(&path)?, selected_stamp);
            assert_eq!(
                fs.inner.metrics().tail_reads - acquisitions,
                1,
                "one failed acquisition per pass"
            );
            assert_eq!(
                report.outcome,
                PassOutcome::CatchingUp,
                "unstable={unstable}: {report:?}"
            );
            assert_eq!(report.failure, Some(FailureCode::SourceChanging));
            assert_eq!(report.records_committed, 0);
            assert_eq!(rows(&world.history()?, &id)?, before);
            assert_eq!(file_state(&world.history()?, &id, &relative)?, old_state);
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                    &[&id]
                )?,
                10
            );
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT generation FROM sources WHERE source_id = ?1",
                    &[&id]
                )?,
                generation
            );
            assert!(
                count(
                    &world.history()?,
                    "SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1",
                    &[&id]
                )? > 0
            );
            if reopen {
                drop(engine);
                (engine, _) = world.engine(fs.clone())?;
            }
            let recovered = drain(&mut engine, &id, DAY_NOW + 2000, 6)?;
            assert_eq!(
                recovered
                    .iter()
                    .map(|report| report.records_committed)
                    .sum::<u32>(),
                1
            );
            let after = rows(&world.history()?, &id)?;
            assert_eq!(after.len(), 1);
            assert_eq!(after[0]["input_tokens"], 20);
            assert_eq!(after[0]["revision"], 2);
            assert_eq!(
                pass(&mut engine, &id, DAY_NOW + 10_000).records_committed,
                0
            );
            assert_eq!(rows(&world.history()?, &id)?, after);
        }
    }
    Ok(())
}

fn cached_confirmation_budget_after_positive_publication(codex: bool) -> TestResult {
    let world = World::new()?;
    let relative = reported_path(codex, "present");
    world.put(&relative, &reported_bytes(codex, "own", "present", 10))?;
    let blocked = world
        .root
        .join(if codex { "sessions/blocked" } else { "queued" });
    std::fs::create_dir_all(&blocked)?;
    let new_relative = reported_path(codex, "new");
    world.put(
        &new_relative,
        if codex {
            b""
        } else {
            br#"{"role":"user","time":{"created":1774785600000}}"#
        },
    )?;
    let fs = ReversedFs::new();
    let (mut engine, id) = reported_engine(&world, fs.clone(), codex)?;
    drain(&mut engine, &id, DAY_NOW, 4)?;
    *fs.directory_fault.lock().map_err(|_| "fault lock")? = Some(blocked.clone());
    assert_ne!(
        pass(&mut engine, &id, DAY_NOW + 1000).outcome,
        PassOutcome::Consistent
    );
    *fs.directory_fault.lock().map_err(|_| "fault lock")? = None;
    let generation = count(
        &world.history()?,
        "SELECT generation FROM sources WHERE source_id = ?1",
        &[&id],
    )?;
    let last_good = count(
        &world.history()?,
        "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
        &[&id],
    )?;
    world.put(&new_relative, &reported_bytes(codex, "new", "new", 11))?;
    *fs.confirmation_budget.lock().map_err(|_| "fault lock")? = Some(blocked.clone());
    let physical_before = physical_operations().metadata;
    let report = pass(&mut engine, &id, DAY_NOW + 2000);
    assert_eq!(
        report.outcome,
        PassOutcome::CatchingUp,
        "codex={codex}: {report:?}"
    );
    assert!(
        report.records_committed > 0,
        "earlier valid publication: {report:?}"
    );
    assert_eq!(report.counters.stat_calls, 40_000);
    assert_eq!(physical_operations().metadata - physical_before, 40_000);
    assert_last_good(&world, &engine, &id, &report, last_good)?;
    assert_eq!(
        count(
            &world.history()?,
            "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
            &[&id]
        )?,
        21
    );
    assert_eq!(
        count(
            &world.history()?,
            "SELECT generation FROM sources WHERE source_id = ?1",
            &[&id]
        )?,
        generation
    );
    assert_eq!(
        count(
            &world.history()?,
            "SELECT dirty FROM sources WHERE source_id = ?1",
            &[&id]
        )?,
        1
    );
    let snapshot = serde_json::to_value(
        engine
            .today_snapshot("UTC", DAY_NOW + 2000)
            .map_err(|error| format!("{error:?}"))?,
    )?;
    assert_eq!(
        snapshot["source_reported"][0]["input"]["status"],
        "catching_up"
    );
    let pending = blocked
        .strip_prefix(&world.root)?
        .to_str()
        .ok_or("pending path")?;
    assert_eq!(
        count(
            &world.history()?,
            "SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1 AND relative_path = ?2",
            &[&id, &pending]
        )?,
        1
    );
    assert_eq!(
        count(
            &world.history()?,
            "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND file_state = 'missing'",
            &[&id]
        )?,
        0
    );
    let after = rows(&world.history()?, &id)?;
    drop(engine);
    *fs.confirmation_budget.lock().map_err(|_| "fault lock")? = None;
    (engine, _) = reported_engine(&world, fs, codex)?;
    assert_last_good(&world, &engine, &id, &report, last_good)?;
    drain(&mut engine, &id, DAY_NOW + 3000, 6)?;
    assert_eq!(rows(&world.history()?, &id)?, after);
    assert_eq!(
        count(
            &world.history()?,
            "SELECT generation FROM sources WHERE source_id = ?1",
            &[&id]
        )?,
        generation + 1
    );
    assert_eq!(
        count(
            &world.history()?,
            "SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1",
            &[&id]
        )?,
        0
    );
    Ok(())
}

#[test]
fn codex_cached_confirmation_budget_after_positive_publication() -> TestResult {
    cached_confirmation_budget_after_positive_publication(true)
}

#[test]
fn opencode_cached_confirmation_budget_after_positive_publication() -> TestResult {
    cached_confirmation_budget_after_positive_publication(false)
}

#[test]
fn ordinary_valid_catching_up_publication_advances_last_good() -> TestResult {
    use std::sync::atomic::{AtomicBool, Ordering};
    for codex in [true, false] {
        let world = World::new()?;
        let first = reported_path(codex, "first");
        let second = reported_path(codex, "second");
        world.put(&first, &reported_bytes(codex, "first", "first", 10))?;
        world.put(&second, &reported_bytes(codex, "second", "second", 20))?;
        let fs = ReversedFs::new();
        let (mut engine, id) = reported_engine(&world, fs.clone(), codex)?;
        drain(&mut engine, &id, DAY_NOW, 4)?;
        world.put(&first, &reported_bytes(codex, "first", "first", 11))?;
        world.history()?.execute("UPDATE source_files SET visit_seq = CASE WHEN relative_path = ?2 THEN 0 ELSE 1 END WHERE source_id = ?1", rusqlite::params![id, first])?;
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&cancel);
        if codex {
            quotern_core::adapters::codex::set_file_commit_hook(Some(Box::new(move || {
                flag.store(true, Ordering::Release)
            })));
        } else {
            let target = world.root.join(&second);
            fs.inner.on_boundary(move |kind, path| {
                if kind == quotern_core::ingest::fs::OpenKind::Bounded && path == target {
                    flag.store(true, Ordering::Release);
                }
            });
        }
        let result = engine.pass_until(&id, enabled(), DAY_NOW + 1000, &cancel);
        quotern_core::adapters::codex::set_file_commit_hook(None);
        fs.inner.on_boundary(|_, _| {});
        let report = result.expect_err("cancelled pass").0;
        assert_eq!(
            report.outcome,
            PassOutcome::CatchingUp,
            "codex={codex}: {report:?}"
        );
        assert!(report.records_committed > 0);
        assert_eq!(report.failure, None);
        assert_last_good(&world, &engine, &id, &report, DAY_NOW + 1000)?;
        assert_eq!(
            count(
                &world.history()?,
                "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                &[&id]
            )?,
            31
        );
        assert_eq!(rows(&world.history()?, &id)?.len(), 2);
        cancel.store(false, Ordering::Release);
        drain(&mut engine, &id, DAY_NOW + 2000, 6)?;
        assert_eq!(
            count(
                &world.history()?,
                "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                &[&id]
            )?,
            31
        );
    }
    Ok(())
}

#[test]
fn per_file_identity_budget_after_positive_publication_preserves_freshness() -> TestResult {
    for codex in [true, false] {
        for (data_identity, reopen) in [(false, false), (false, true), (true, false), (true, true)]
        {
            let world = World::new()?;
            let first = reported_path(codex, "first");
            let second = reported_path(codex, "second");
            world.put(&first, &reported_bytes(codex, "first", "first", 10))?;
            world.put(&second, &reported_bytes(codex, "second", "second", 20))?;
            let fs = ReversedFs::new();
            let (mut engine, id) = reported_engine(&world, fs.clone(), codex)?;
            drain(&mut engine, &id, DAY_NOW, 4)?;
            let old_second = file_state(&world.history()?, &id, &second)?;
            let generation = count(
                &world.history()?,
                "SELECT generation FROM sources WHERE source_id = ?1",
                &[&id],
            )?;
            let last_good = count(
                &world.history()?,
                "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
                &[&id],
            )?;
            world.put(&first, &reported_bytes(codex, "first", "first", 11))?;
            world.put(&second, &reported_bytes(codex, "second", "second", 21))?;
            world.history()?.execute("UPDATE source_files SET visit_seq = CASE WHEN relative_path = ?2 THEN 0 ELSE 1 END WHERE source_id = ?1", rusqlite::params![id, first])?;
            let target = if data_identity {
                world.data.clone()
            } else {
                world.root.clone()
            };
            *fs.budget_at_file.lock().map_err(|_| "file budget lock")? =
                Some((world.root.join(&second), target));
            let physical_before = physical_operations().metadata;
            let report = pass(&mut engine, &id, DAY_NOW + 1000);
            assert_eq!(
                report.outcome,
                PassOutcome::CatchingUp,
                "codex={codex}, data={data_identity}: {report:?}"
            );
            assert!(report.records_committed > 0);
            assert_eq!(report.counters.stat_calls, 40_000);
            assert_eq!(physical_operations().metadata - physical_before, 40_000);
            assert_last_good(&world, &engine, &id, &report, last_good)?;
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                    &[&id]
                )?,
                31
            );
            assert_eq!(file_state(&world.history()?, &id, &second)?, old_second);
            assert_eq!(rows(&world.history()?, &id)?.len(), 2);
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT generation FROM sources WHERE source_id = ?1",
                    &[&id]
                )?,
                generation
            );
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT dirty FROM sources WHERE source_id = ?1",
                    &[&id]
                )?,
                1
            );
            assert!(
                count(
                    &world.history()?,
                    "SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1",
                    &[&id]
                )? > 0
            );
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND file_state = 'missing'",
                    &[&id]
                )?,
                0
            );
            *fs.metadata_budget.lock().map_err(|_| "budget lock")? = None;
            if reopen {
                drop(engine);
                (engine, _) = reported_engine(&world, fs.clone(), codex)?;
            }
            assert_last_good(&world, &engine, &id, &report, last_good)?;
            drain(&mut engine, &id, DAY_NOW + 2000, 6)?;
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                    &[&id]
                )?,
                32
            );
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT generation FROM sources WHERE source_id = ?1",
                    &[&id]
                )?,
                generation + 1
            );
            let after = rows(&world.history()?, &id)?;
            assert_eq!(after.len(), 2);
            assert!(after.iter().all(|row| row["revision"] == 2));
            pass(&mut engine, &id, DAY_NOW + 10_000);
            assert_eq!(rows(&world.history()?, &id)?, after);
        }
    }
    Ok(())
}

#[test]
fn opencode_root_replacement_after_sqlite_preflight_refuses_batch() -> TestResult {
    let world = World::new()?;
    let database = world.root.join("opencode.db");
    let connection = Connection::open(&database)?;
    let schema = include_str!("../../../Fixtures/harness/opencode/wal/schema.sql")
        .lines()
        .filter(|line| !line.trim_start().starts_with("PRAGMA"))
        .collect::<Vec<_>>()
        .join("\n");
    connection.execute_batch(&schema)?;
    let original = reported_bytes(false, "own", "present", 10);
    connection.execute(
        "INSERT INTO message(id, session_id, time_created, data) VALUES ('present', 'own', ?1, ?2)",
        rusqlite::params![DAY_NOW, original],
    )?;
    drop(connection);
    let fs = ReversedFs::new();
    let (mut engine, id) = reported_engine(&world, fs.clone(), false)?;
    drain(&mut engine, &id, DAY_NOW, 4)?;
    let before = rows(&world.history()?, &id)?;
    assert_eq!(before.len(), 1);
    assert_eq!(before[0]["input_tokens"], 10);
    let generation = count(
        &world.history()?,
        "SELECT generation FROM sources WHERE source_id = ?1",
        &[&id],
    )?;
    let last_good = count(
        &world.history()?,
        "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
        &[&id],
    )?;
    let old_state = file_state(&world.history()?, &id, "opencode.db")?;
    let connection = Connection::open(&database)?;
    connection.execute(
        "UPDATE message SET data = ?1 WHERE id = 'present'",
        [reported_bytes(false, "own", "present", 11)],
    )?;
    drop(connection);
    let selected = independent_stamp(&database)?;
    let root = world.root.clone();
    let target = database.clone();
    let moved = world._directory.path().join("registered-root");
    let saved = moved.clone();
    fs.inner.on_boundary(move |kind, path| {
        if kind == quotern_core::ingest::fs::OpenKind::Sqlite && path == target {
            std::fs::rename(&root, &saved).expect("move root after database preflight");
            std::fs::create_dir(&root).expect("create substitute root");
            // The database witness stays equal; only the registered directory identity changes.
            std::fs::rename(saved.join("opencode.db"), &target)
                .expect("retain database identity beneath substitute");
        }
    });
    let report = pass(&mut engine, &id, DAY_NOW + 1000);
    fs.inner.on_boundary(|_, _| {});
    assert_eq!(independent_stamp(&database)?, selected);
    assert_eq!(report.failure, Some(FailureCode::RootOverlap), "{report:?}");
    assert_eq!(
        report.records_committed, 0,
        "root identity must be checked before accepting the batch"
    );
    assert_last_good(&world, &engine, &id, &report, last_good)?;
    assert_eq!(rows(&world.history()?, &id)?, before);
    assert_eq!(
        file_state(&world.history()?, &id, "opencode.db")?,
        old_state
    );
    assert_eq!(
        count(
            &world.history()?,
            "SELECT generation FROM sources WHERE source_id = ?1",
            &[&id]
        )?,
        generation
    );
    assert_eq!(
        count(
            &world.history()?,
            "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND file_state = 'missing'",
            &[&id]
        )?,
        0
    );
    std::fs::rename(&database, moved.join("opencode.db"))?;
    std::fs::remove_dir(&world.root)?;
    std::fs::rename(moved, &world.root)?;
    drop(engine);
    (engine, _) = reported_engine(&world, fs, false)?;
    drain(&mut engine, &id, DAY_NOW + 2000, 6)?;
    let after = rows(&world.history()?, &id)?;
    assert_eq!(after.len(), 1);
    assert_eq!(after[0]["input_tokens"], 11);
    assert_eq!(after[0]["revision"], 2);
    pass(&mut engine, &id, DAY_NOW + 10_000);
    assert_eq!(rows(&world.history()?, &id)?, after);
    Ok(())
}

#[test]
fn refused_root_recovery_at_full_frontier_preserves_work_and_drains() -> TestResult {
    for codex in [true, false] {
        for reopen in [false, true] {
            let world = World::new()?;
            let present = reported_path(codex, "present");
            let removed = reported_path(codex, "removed");
            let unseen = reported_path(codex, "unseen");
            world.put(&present, &reported_bytes(codex, "own", "present", 10))?;
            world.put(&removed, &reported_bytes(codex, "own", "removed", 20))?;
            let fs = ReversedFs::new();
            let (mut engine, id) = reported_engine(&world, fs.clone(), codex)?;
            drain(&mut engine, &id, DAY_NOW, 4)?;
            let generation = count(
                &world.history()?,
                "SELECT generation FROM sources WHERE source_id = ?1",
                &[&id],
            )?;
            let last_good = count(
                &world.history()?,
                "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
                &[&id],
            )?;
            let old_rows = rows(&world.history()?, &id)?;
            let mut connection = world.history()?;
            let transaction = connection.transaction()?;
            for index in 0..4096 {
                let relative = format!("queued/d{index:04}");
                std::fs::create_dir_all(world.root.join(&relative))?;
                transaction.execute("INSERT INTO frontier_directories(source_id, generation, relative_path, depth, ordinal, restart_blocked) VALUES(?1, ?2, ?3, 2, ?4, 0)", rusqlite::params![id, generation, relative, index])?;
            }
            let stamp = independent_stamp(&world.root)?;
            transaction.execute("INSERT INTO metadata_spool(source_id, generation, relative_path, device, inode, size, mtime_ns, parser_kind) VALUES(?1, ?2, '', ?3, ?4, ?5, ?6, 'directory')", rusqlite::params![id, generation, stamp.0 as i64, stamp.1 as i64, stamp.2 as i64, stamp.3])?;
            transaction.commit()?;
            drop(connection);
            drop(engine);
            (engine, _) = reported_engine(&world, fs.clone(), codex)?;
            std::fs::remove_file(world.root.join(&removed))?;
            world.put(&unseen, &reported_bytes(codex, "own", "unseen", 7))?;
            let root = world.root.clone();
            let target = root.join("queued/d0000");
            let moved = world._directory.path().join("registered-root");
            let saved = moved.clone();
            fs.inner.on_boundary(move |kind, path| {
                if kind == quotern_core::ingest::fs::OpenKind::Directory && path == target {
                    std::fs::rename(&root, &saved).expect("move registered root at full queue");
                    std::fs::create_dir(&root).expect("install empty substitute root");
                }
            });
            let report = pass(&mut engine, &id, DAY_NOW + 1000);
            fs.inner.on_boundary(|_, _| {});
            assert_eq!(report.failure, Some(FailureCode::RootOverlap), "{report:?}");
            assert_last_good(&world, &engine, &id, &report, last_good)?;
            assert_eq!(rows(&world.history()?, &id)?, old_rows);
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT COUNT(*) FROM metadata_spool WHERE source_id = ?1",
                    &[&id]
                )?,
                0
            );
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1",
                    &[&id]
                )?,
                4096
            );
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1 AND relative_path LIKE 'queued/d____'",
                    &[&id]
                )?,
                4096
            );
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT generation FROM sources WHERE source_id = ?1",
                    &[&id]
                )?,
                generation
            );
            assert_within_caps(&report.counters, "full queue refusal");
            std::fs::rename(&world.root, world._directory.path().join("rejected-root"))?;
            std::fs::rename(moved, &world.root)?;
            if reopen {
                drop(engine);
                (engine, _) = reported_engine(&world, fs.clone(), codex)?;
            }
            let mut terminal = false;
            for step in 1..=100 {
                let report = pass(&mut engine, &id, DAY_NOW + 1000 + step * 1000);
                assert_within_caps(&report.counters, "full queue recovery");
                assert!(
                    count(
                        &world.history()?,
                        "SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1",
                        &[&id]
                    )? <= 4096
                );
                if report.outcome == PassOutcome::Consistent {
                    terminal = true;
                    break;
                }
                assert_eq!(report.outcome, PassOutcome::CatchingUp, "{report:?}");
            }
            assert!(terminal, "finite full queue must drain");
            let recovered = rows(&world.history()?, &id)?;
            assert_eq!(recovered.len(), 3);
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                    &[&id]
                )?,
                37
            );
            assert_eq!(
                source_membership(&world.history()?, &id)?,
                vec![
                    (present, "present".into()),
                    (removed, "missing".into()),
                    (unseen, "present".into())
                ]
            );
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT generation FROM sources WHERE source_id = ?1",
                    &[&id]
                )?,
                generation + 1
            );
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1",
                    &[&id]
                )?,
                0
            );
            pass(&mut engine, &id, DAY_NOW + 200_000);
            assert_eq!(rows(&world.history()?, &id)?, recovered);
        }
    }
    Ok(())
}

#[test]
fn terminal_root_replacement_with_identity_budget_rediscovers_after_restoration() -> TestResult {
    for codex in [true, false] {
        for data_identity in [false, true] {
            for reopen in [false, true] {
                let world = World::new()?;
                let present = reported_path(codex, "present");
                let removed = reported_path(codex, "removed");
                let unseen = reported_path(codex, "unseen");
                world.put(&present, &reported_bytes(codex, "own", "present", 10))?;
                world.put(&removed, &reported_bytes(codex, "own", "removed", 20))?;
                let fs = ReversedFs::new();
                let (mut engine, id) = reported_engine(&world, fs.clone(), codex)?;
                drain(&mut engine, &id, DAY_NOW, 4)?;
                let generation = count(
                    &world.history()?,
                    "SELECT generation FROM sources WHERE source_id = ?1",
                    &[&id],
                )?;
                let last_good = count(
                    &world.history()?,
                    "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
                    &[&id],
                )?;
                world.put(&present, &reported_bytes(codex, "own", "present", 11))?;
                std::fs::remove_file(world.root.join(&removed))?;
                world.put(&unseen, &reported_bytes(codex, "own", "unseen", 7))?;
                let root = world.root.clone();
                let moved = world._directory.path().join("registered-root");
                let saved = moved.clone();
                let target = if data_identity {
                    world.data.clone()
                } else {
                    root.clone()
                };
                let listing_swap = Arc::clone(&fs.listing_swap);
                let contents = world._directory.path().join("registered-content");
                std::fs::create_dir(&contents)?;
                let moved_contents = contents.clone();
                let rejected = world._directory.path().join("rejected-root");
                fs.inner.on_boundary(move |kind, path| {
                    if kind == quotern_core::ingest::fs::OpenKind::Directory && path == root {
                        // Empty the original inode for a genuine native EOF. The private listing
                        // hook substitutes the root only after that acquisition has completed.
                        for entry in std::fs::read_dir(&root).expect("root contents") {
                            let entry = entry.expect("root entry");
                            std::fs::rename(entry.path(), moved_contents.join(entry.file_name()))
                                .expect("temporarily remove root content");
                        }
                        *listing_swap.lock().expect("listing swap lock") = Some(ListingSwap {
                            root: root.clone(),
                            saved: saved.clone(),
                            budget_target: target.clone(),
                            restore_before_proof: data_identity.then(|| rejected.clone()),
                        });
                    }
                });
                let before = physical_operations();
                let report = pass(&mut engine, &id, DAY_NOW + 1000);
                let after = physical_operations();
                fs.inner.on_boundary(|_, _| {});
                assert_eq!(report.outcome, PassOutcome::CatchingUp, "{report:?}");
                assert_eq!(report.counters.stat_calls, 40_000);
                assert_eq!(after.metadata - before.metadata, 40_000);
                assert!(report.records_committed > 0);
                assert_last_good(&world, &engine, &id, &report, last_good)?;
                assert_eq!(
                    count(
                        &world.history()?,
                        "SELECT generation FROM sources WHERE source_id = ?1",
                        &[&id]
                    )?,
                    generation
                );
                assert_eq!(
                    count(
                        &world.history()?,
                        "SELECT COUNT(*) FROM metadata_spool WHERE source_id = ?1 AND relative_path = '' AND parser_kind = 'directory'",
                        &[&id]
                    )?,
                    0,
                    "unverified root completion must remain retryable"
                );
                assert_eq!(
                    count(
                        &world.history()?,
                        "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND file_state = 'missing'",
                        &[&id]
                    )?,
                    0
                );
                *fs.metadata_budget.lock().map_err(|_| "budget lock")? = None;
                if !data_identity {
                    std::fs::rename(&world.root, world._directory.path().join("rejected-root"))?;
                    std::fs::rename(moved, &world.root)?;
                }
                for entry in std::fs::read_dir(&contents)? {
                    let entry = entry?;
                    std::fs::rename(entry.path(), world.root.join(entry.file_name()))?;
                }
                if reopen {
                    drop(engine);
                    (engine, _) = reported_engine(&world, fs.clone(), codex)?;
                }
                drain(&mut engine, &id, DAY_NOW + 2000, 6)?;
                let recovered = rows(&world.history()?, &id)?;
                assert_eq!(recovered.len(), 3);
                assert_eq!(
                    count(
                        &world.history()?,
                        "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                        &[&id]
                    )?,
                    38
                );
                assert_eq!(
                    source_membership(&world.history()?, &id)?,
                    vec![
                        (present, "present".into()),
                        (removed, "missing".into()),
                        (unseen, "present".into())
                    ]
                );
                assert_eq!(
                    count(
                        &world.history()?,
                        "SELECT generation FROM sources WHERE source_id = ?1",
                        &[&id]
                    )?,
                    generation + 1
                );
                pass(&mut engine, &id, DAY_NOW + 10_000);
                assert_eq!(rows(&world.history()?, &id)?, recovered);
            }
        }
    }
    Ok(())
}

#[test]
fn ordinary_frontier_budget_publication_advances_last_good() -> TestResult {
    for codex in [true, false] {
        let world = World::new()?;
        let relative = reported_path(codex, "present");
        world.put(&relative, &reported_bytes(codex, "own", "present", 10))?;
        let fs = ReversedFs::new();
        let (mut engine, id) = reported_engine(&world, fs, codex)?;
        drain(&mut engine, &id, DAY_NOW, 4)?;
        world.put(&relative, &reported_bytes(codex, "own", "present", 11))?;
        for index in 0..100 {
            std::fs::create_dir_all(world.root.join(format!("sessions/old/d{index:03}")))?;
        }
        let report = pass(&mut engine, &id, DAY_NOW + 1000);
        assert_eq!(report.outcome, PassOutcome::CatchingUp, "{report:?}");
        assert_eq!(report.failure, None);
        assert!(report.records_committed > 0);
        assert_eq!(report.counters.directory_opens, 64);
        assert_within_caps(&report.counters, "ordinary frontier budget");
        assert_last_good(&world, &engine, &id, &report, DAY_NOW + 1000)?;
        assert_eq!(
            count(
                &world.history()?,
                "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                &[&id]
            )?,
            11
        );
        drain(&mut engine, &id, DAY_NOW + 2000, 6)?;
        assert_eq!(rows(&world.history()?, &id)?.len(), 1);
    }
    Ok(())
}

#[test]
fn initial_selection_and_directory_acquisition_budget_preserve_freshness() -> TestResult {
    for codex in [true, false] {
        for acquisition in [false, true] {
            for reopen in [false, true] {
                let world = World::new()?;
                let present = reported_path(codex, "present");
                world.put(&present, &reported_bytes(codex, "own", "present", 10))?;
                let fs = ReversedFs::new();
                let (mut engine, id) = reported_engine(&world, fs.clone(), codex)?;
                drain(&mut engine, &id, DAY_NOW, 4)?;
                let generation = count(
                    &world.history()?,
                    "SELECT generation FROM sources WHERE source_id = ?1",
                    &[&id],
                )?;
                let last_good = count(
                    &world.history()?,
                    "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
                    &[&id],
                )?;
                let blocked = world
                    .root
                    .join(if codex { "sessions/blocked" } else { "blocked" });
                if acquisition {
                    std::fs::create_dir_all(&blocked)?;
                }
                let relative = blocked
                    .strip_prefix(&world.root)?
                    .to_str()
                    .ok_or("blocked path")?;
                let connection = world.history()?;
                connection.execute("INSERT INTO frontier_directories(source_id, generation, relative_path, depth, ordinal, restart_blocked) VALUES(?1, ?2, ?3, 2, 0, 0)", rusqlite::params![id, generation, relative])?;
                let stamp = independent_stamp(&world.root)?;
                connection.execute("INSERT INTO metadata_spool(source_id, generation, relative_path, device, inode, size, mtime_ns, parser_kind) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)", rusqlite::params![id, generation, "", stamp.0 as i64, stamp.1 as i64, stamp.2 as i64, stamp.3, "directory"])?;
                drop(connection);
                drop(engine);
                (engine, _) = reported_engine(&world, fs.clone(), codex)?;
                world.put(&present, &reported_bytes(codex, "own", "present", 11))?;
                if acquisition {
                    *fs.acquisition_budget.lock().map_err(|_| "budget lock")? =
                        Some(blocked.clone());
                } else {
                    *fs.budget_at_file.lock().map_err(|_| "budget lock")? =
                        Some((blocked.clone(), world.root.clone()));
                }
                let before = physical_operations();
                let report = pass(&mut engine, &id, DAY_NOW + 1000);
                let after = physical_operations();
                assert_eq!(
                    report.outcome,
                    PassOutcome::CatchingUp,
                    "codex={codex}, acquisition={acquisition}: {report:?}"
                );
                assert!(
                    report.records_committed > 0,
                    "earlier valid publication: {report:?}"
                );
                assert_eq!(report.counters.stat_calls, 40_000);
                assert_eq!(after.metadata - before.metadata, 40_000);
                assert_last_good(&world, &engine, &id, &report, last_good)?;
                assert_eq!(
                    count(
                        &world.history()?,
                        "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                        &[&id]
                    )?,
                    11
                );
                assert_eq!(
                    count(
                        &world.history()?,
                        "SELECT generation FROM sources WHERE source_id = ?1",
                        &[&id]
                    )?,
                    generation
                );
                assert_eq!(
                    count(
                        &world.history()?,
                        "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND file_state = ?2",
                        &[&id, &"missing"]
                    )?,
                    0
                );
                assert_eq!(
                    count(
                        &world.history()?,
                        "SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1 AND relative_path = ?2",
                        &[&id, &relative]
                    )?,
                    1
                );
                *fs.acquisition_budget.lock().map_err(|_| "budget lock")? = None;
                *fs.metadata_budget.lock().map_err(|_| "budget lock")? = None;
                if reopen {
                    drop(engine);
                    (engine, _) = reported_engine(&world, fs.clone(), codex)?;
                }
                assert_last_good(&world, &engine, &id, &report, last_good)?;
                drain(&mut engine, &id, DAY_NOW + 2000, 6)?;
                assert_eq!(
                    count(
                        &world.history()?,
                        "SELECT generation FROM sources WHERE source_id = ?1",
                        &[&id]
                    )?,
                    generation + 1
                );
                assert_eq!(rows(&world.history()?, &id)?.len(), 1);
            }
        }
    }
    Ok(())
}

#[test]
fn nested_completed_ancestor_budget_recovery_at_full_frontier() -> TestResult {
    for codex in [true, false] {
        for reopen in [false, true] {
            let world = World::new()?;
            let present = reported_path(codex, "present");
            let removed = reported_path(codex, "removed");
            let unseen = reported_path(codex, "unseen");
            world.put(&present, &reported_bytes(codex, "own", "present", 10))?;
            world.put(&removed, &reported_bytes(codex, "own", "removed", 20))?;
            let fs = ReversedFs::new();
            let (mut engine, id) = reported_engine(&world, fs.clone(), codex)?;
            drain(&mut engine, &id, DAY_NOW, 4)?;
            let generation = count(
                &world.history()?,
                "SELECT generation FROM sources WHERE source_id = ?1",
                &[&id],
            )?;
            let last_good = count(
                &world.history()?,
                "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
                &[&id],
            )?;
            let d = world.root.join(&present).parent().ok_or("D")?.to_path_buf();
            let p = d.parent().ok_or("P")?.to_path_buf();
            let blocked = world
                .root
                .join(if codex { "sessions/missing" } else { "missing" });
            let mut connection = world.history()?;
            let transaction = connection.transaction()?;
            for (index, path) in std::iter::once(d.clone())
                .chain((1..4096).map(|index| {
                    if index == 8 {
                        blocked.clone()
                    } else {
                        world.root.join(format!("queued/d{index:04}"))
                    }
                }))
                .enumerate()
            {
                if path != blocked {
                    std::fs::create_dir_all(&path)?;
                }
                let relative = path.strip_prefix(&world.root)?.to_str().ok_or("relative")?;
                transaction.execute("INSERT INTO frontier_directories(source_id, generation, relative_path, depth, ordinal, restart_blocked) VALUES(?1, ?2, ?3, ?4, ?5, 0)", rusqlite::params![id, generation, relative, path.strip_prefix(&world.root)?.components().count() as i64, index as i64])?;
            }
            for path in p
                .ancestors()
                .take_while(|path| path.starts_with(&world.root))
            {
                let stamp = independent_stamp(path)?;
                let relative = path.strip_prefix(&world.root)?.to_str().ok_or("ancestor")?;
                transaction.execute("INSERT INTO metadata_spool(source_id, generation, relative_path, device, inode, size, mtime_ns, parser_kind) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)", rusqlite::params![id, generation, relative, stamp.0 as i64, stamp.1 as i64, stamp.2 as i64, stamp.3, "directory"])?;
            }
            transaction.commit()?;
            drop(connection);
            drop(engine);
            (engine, _) = reported_engine(&world, fs.clone(), codex)?;
            std::fs::remove_file(world.root.join(&removed))?;
            world.put(&unseen, &reported_bytes(codex, "own", "unseen", 7))?;
            let saved = world._directory.path().join("saved-D");
            std::fs::create_dir(&saved)?;
            let target = d.clone();
            let moved = saved.clone();
            fs.inner.on_boundary(move |kind, path| {
                if kind == quotern_core::ingest::fs::OpenKind::Directory && path == target {
                    // Keep the selected inode: an empty EOF must genuinely complete D before
                    // the later proof refusal exercises the full-queue ancestor fallback.
                    for entry in std::fs::read_dir(&target).expect("D contents") {
                        let entry = entry.expect("D entry");
                        std::fs::rename(entry.path(), moved.join(entry.file_name()))
                            .expect("temporarily remove D content");
                    }
                }
            });
            *fs.budget_at_file.lock().map_err(|_| "budget lock")? =
                Some((blocked.clone(), world.root.clone()));
            let before = physical_operations();
            let report = pass(&mut engine, &id, DAY_NOW + 1000);
            let after = physical_operations();
            fs.inner.on_boundary(|_, _| {});
            assert_eq!(report.outcome, PassOutcome::CatchingUp, "{report:?}");
            assert_eq!(report.counters.stat_calls, 40_000);
            assert_eq!(after.metadata - before.metadata, 40_000);
            assert_last_good(&world, &engine, &id, &report, last_good)?;
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1",
                    &[&id]
                )?,
                4096
            );
            let relative_p = p.strip_prefix(&world.root)?.to_str().ok_or("P path")?;
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT COUNT(*) FROM metadata_spool WHERE source_id = ?1 AND relative_path = ?2 AND parser_kind = ?3",
                    &[&id, &relative_p, &"directory"]
                )?,
                0,
                "overflow recovery must reopen the completed ancestor route"
            );
            for entry in std::fs::read_dir(&saved)? {
                let entry = entry?;
                std::fs::rename(entry.path(), d.join(entry.file_name()))?;
            }
            *fs.metadata_budget.lock().map_err(|_| "budget lock")? = None;
            if reopen {
                drop(engine);
                (engine, _) = reported_engine(&world, fs.clone(), codex)?;
            }
            drain(&mut engine, &id, DAY_NOW + 2000, 100)?;
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                    &[&id]
                )?,
                37
            );
            assert_eq!(
                source_membership(&world.history()?, &id)?,
                vec![
                    (present, "present".into()),
                    (removed, "missing".into()),
                    (unseen, "present".into())
                ]
            );
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT generation FROM sources WHERE source_id = ?1",
                    &[&id]
                )?,
                generation + 1
            );
        }
    }
    Ok(())
}

#[test]
fn ordinary_initial_metadata_budget_publication_advances_last_good() -> TestResult {
    for codex in [true, false] {
        for reopen in [false, true] {
            let world = World::new()?;
            let first = reported_path(codex, "first");
            let second = reported_path(codex, "second");
            world.put(&first, &reported_bytes(codex, "first", "first", 10))?;
            world.put(&second, &reported_bytes(codex, "second", "second", 20))?;
            let fs = ReversedFs::new();
            let (mut engine, id) = reported_engine(&world, fs.clone(), codex)?;
            drain(&mut engine, &id, DAY_NOW, 4)?;
            world.put(&first, &reported_bytes(codex, "first", "first", 11))?;
            world.history()?.execute("UPDATE source_files SET visit_seq = CASE WHEN relative_path = ?2 THEN 0 ELSE 1 END WHERE source_id = ?1", rusqlite::params![id, first])?;
            let target = world.root.join(&second);
            *fs.budget_at_file.lock().map_err(|_| "budget lock")? = Some((target.clone(), target));
            let before = physical_operations();
            let report = pass(&mut engine, &id, DAY_NOW + 1000);
            let after = physical_operations();
            assert_eq!(report.outcome, PassOutcome::CatchingUp, "{report:?}");
            assert_eq!(report.failure, None);
            assert!(report.records_committed > 0);
            assert_eq!(report.counters.stat_calls, 40_000);
            assert_eq!(after.metadata - before.metadata, 40_000);
            assert_last_good(&world, &engine, &id, &report, DAY_NOW + 1000)?;
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                    &[&id]
                )?,
                31
            );
            *fs.metadata_budget.lock().map_err(|_| "budget lock")? = None;
            if reopen {
                drop(engine);
                (engine, _) = reported_engine(&world, fs.clone(), codex)?;
            }
            drain(&mut engine, &id, DAY_NOW + 2000, 6)?;
            assert_eq!(rows(&world.history()?, &id)?.len(), 2);
        }
    }
    Ok(())
}

#[test]
fn codex_missing_entry_confirmation_budget_preserves_freshness() -> TestResult {
    for reopen in [false, true] {
        let world = World::new()?;
        let present = reported_path(true, "present");
        world.put(&present, &reported_bytes(true, "own", "present", 10))?;
        let fs = ReversedFs::new();
        let (mut engine, id) = world.engine(fs.clone())?;
        drain(&mut engine, &id, DAY_NOW, 4)?;
        let generation = count(
            &world.history()?,
            "SELECT generation FROM sources WHERE source_id = ?1",
            &[&id],
        )?;
        let last_good = count(
            &world.history()?,
            "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
            &[&id],
        )?;
        let connection = world.history()?;
        connection.execute("INSERT INTO frontier_directories(source_id, generation, relative_path, depth, ordinal, restart_blocked) VALUES(?1, ?2, ?3, 2, 0, 0)", rusqlite::params![id, generation, "sessions/old"])?;
        let stamp = independent_stamp(&world.root)?;
        connection.execute("INSERT INTO metadata_spool(source_id, generation, relative_path, device, inode, size, mtime_ns, parser_kind) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)", rusqlite::params![id, generation, "", stamp.0 as i64, stamp.1 as i64, stamp.2 as i64, stamp.3, "directory"])?;
        drop(connection);
        drop(engine);
        (engine, _) = world.engine(fs.clone())?;
        world.put(&present, &reported_bytes(true, "own", "present", 11))?;
        let missing = world.put(
            "sessions/old/z-missing.jsonl",
            &reported_bytes(true, "own", "unseen", 7),
        )?;
        *fs.remove_at_metadata.lock().map_err(|_| "removal lock")? = Some(missing.clone());
        *fs.budget_at_file.lock().map_err(|_| "budget lock")? = Some((missing, world.root.clone()));
        let before = physical_operations();
        let report = pass(&mut engine, &id, DAY_NOW + 1000);
        let after = physical_operations();
        assert!(
            fs.remove_at_metadata
                .lock()
                .map_err(|_| "removal lock")?
                .is_none()
        );
        assert!(report.records_committed > 0);
        assert_eq!(report.outcome, PassOutcome::CatchingUp);
        assert_eq!(report.counters.stat_calls, 40_000);
        assert_eq!(after.metadata - before.metadata, 40_000);
        assert_last_good(&world, &engine, &id, &report, last_good)?;
        assert_eq!(
            count(
                &world.history()?,
                "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                &[&id]
            )?,
            11
        );
        assert_eq!(
            count(
                &world.history()?,
                "SELECT generation FROM sources WHERE source_id = ?1",
                &[&id]
            )?,
            generation
        );
        *fs.metadata_budget.lock().map_err(|_| "budget lock")? = None;
        if reopen {
            drop(engine);
            (engine, _) = world.engine(fs.clone())?;
        }
        assert_last_good(&world, &engine, &id, &report, last_good)?;
        drain(&mut engine, &id, DAY_NOW + 2000, 6)?;
        assert_eq!(rows(&world.history()?, &id)?.len(), 1);
        assert_eq!(
            count(
                &world.history()?,
                "SELECT generation FROM sources WHERE source_id = ?1",
                &[&id]
            )?,
            generation + 1
        );
    }
    Ok(())
}

#[test]
fn part_directory_acquisition_proof_budget_keeps_last_good() -> TestResult {
    for reopen in [false, true] {
        let world = World::new()?;
        let present = reported_path(false, "present");
        world.put(&present, &reported_bytes(false, "own", "present", 10))?;
        let fs = ReversedFs::new();
        let (mut engine, id) = reported_engine(&world, fs.clone(), false)?;
        drain(&mut engine, &id, DAY_NOW, 4)?;
        let last_good = count(
            &world.history()?,
            "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
            &[&id],
        )?;
        world.put(&present, &reported_bytes(false, "own", "present", 11))?;
        world.put(
            &reported_path(false, "z-new"),
            &reported_bytes(false, "own", "z-new", 7),
        )?;
        let directory = world.root.join("storage/part/z-new");
        std::fs::create_dir_all(&directory)?;
        *fs.acquisition_budget.lock().map_err(|_| "budget lock")? = Some(directory);
        let before = physical_operations();
        let report = pass(&mut engine, &id, DAY_NOW + 1000);
        assert_eq!(report.outcome, PassOutcome::CatchingUp, "{report:?}");
        assert!(report.records_committed > 0, "earlier complete publication");
        assert_eq!(report.counters.stat_calls, 40_000);
        assert_eq!(physical_operations().metadata - before.metadata, 40_000);
        assert_last_good(&world, &engine, &id, &report, last_good)?;
        assert_eq!(
            count(
                &world.history()?,
                "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                &[&id]
            )?,
            11
        );
        *fs.acquisition_budget.lock().map_err(|_| "budget lock")? = None;
        if reopen {
            drop(engine);
            (engine, _) = reported_engine(&world, fs.clone(), false)?;
        }
        assert_last_good(&world, &engine, &id, &report, last_good)?;
        drain(&mut engine, &id, DAY_NOW + 2000, 8)?;
        assert_eq!(
            count(
                &world.history()?,
                "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                &[&id]
            )?,
            18
        );
    }
    Ok(())
}

#[test]
fn dated_lane_charges_every_physical_yield_before_stopping() -> TestResult {
    let world = World::new()?;
    for directory in ["sessions/2026/03/29", "sessions/old"] {
        std::fs::create_dir_all(world.root.join(directory))?;
        for index in 0..if directory.ends_with("old") {
            20_001
        } else {
            10_001
        } {
            world.put(&format!("{directory}/ignored-{index:05}.txt"), b"")?;
        }
    }
    let fs = RecordingFs::new();
    let (mut engine, id) = world.engine(fs.clone())?;
    let before = physical_operations();
    let report = pass(&mut engine, &id, DAY_NOW);
    let entries = physical_operations().directory_yields - before.directory_yields;
    assert_eq!(report.counters.entries, 20_000, "{report:?}");
    assert_eq!(
        entries,
        u64::from(report.counters.entries),
        "every physical yield is charged"
    );
    assert_within_caps(&report.counters, "dated lane");
    drain(&mut engine, &id, DAY_NOW + 1000, 10)?;
    assert!(fs.metrics().max_open_directories <= 8);
    Ok(())
}

#[test]
fn growing_unfinished_current_file_does_not_starve_unknown_sibling() -> TestResult {
    for reopen in [false, true] {
        let world = World::new()?;
        let growing = "sessions/old/z-growing.jsonl";
        let mut bytes = reported_bytes(true, "own", "growing", 10);
        for _ in 0..4 {
            bytes.extend_from_slice(b"{}");
            bytes.extend(vec![b' '; 599_997]);
            bytes.push(b'\n');
        }
        world.put(growing, &bytes)?;
        world.put(
            "sessions/old/a-stable.jsonl",
            &reported_bytes(true, "own", "stable", 7),
        )?;
        let fs = ReversedFs::new();
        let (mut engine, id) = world.engine(fs.clone())?;
        for attempt in 0..4 {
            world.append(growing, b" \n")?;
            let report = pass(&mut engine, &id, DAY_NOW + attempt * 1000);
            assert_within_caps(&report.counters, "growing current/history");
            assert_eq!(report.outcome, PassOutcome::CatchingUp);
            if reopen && attempt == 1 {
                drop(engine);
                (engine, _) = world.engine(fs.clone())?;
            }
        }
        let connection = world.history()?;
        assert_eq!(
            count(
                &connection,
                "SELECT COUNT(*) FROM usage_events WHERE source_id = ?1 AND message_id = ?2",
                &[&id, &"stable"]
            )?,
            1,
            "unknown sibling must progress while current file keeps changing"
        );
        drain(&mut engine, &id, DAY_NOW + 10_000, 10)?;
        assert_eq!(
            count(
                &connection,
                "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                &[&id]
            )?,
            17
        );
        assert_eq!(rows(&connection, &id)?.len(), 2);
        assert_eq!(
            pass(&mut engine, &id, DAY_NOW + 100_000).records_committed,
            0
        );
        assert!(
            count(
                &connection,
                "SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1",
                &[&id]
            )? <= 4096
        );
    }
    Ok(())
}

#[test]
fn first_unknown_historical_acquisition_failure_retries_durably() -> TestResult {
    for changing in [false, true] {
        for reopen in [false, true] {
            let world = World::new()?;
            let relative = "sessions/old/z-failed.jsonl";
            let bytes = reported_bytes(true, "own", "failed", 5);
            let target = world.put(relative, &bytes)?;
            let modified = std::fs::metadata(&target)?.modified()?;
            let mut working = reported_bytes(true, "own", "working", 3);
            for _ in 0..3 {
                working.extend_from_slice(b"{}");
                working.extend(vec![b' '; 599_997]);
                working.push(b'\n');
            }
            world.put("sessions/old/a-working.jsonl", &working)?;
            let fs = ReversedFs::new();
            let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            if changing {
                let target = target.clone();
                let attempts = Arc::clone(&attempts);
                fs.inner.on_boundary(move |kind, path| {
                    if kind == quotern_core::ingest::fs::OpenKind::TailRead && path == target {
                        attempts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        std::fs::OpenOptions::new()
                            .append(true)
                            .open(path)
                            .expect("fixture file")
                            .write_all(b" ")
                            .expect("stamp race");
                    }
                });
            } else {
                *fs.tail_fault.lock().map_err(|_| "fault lock")? = Some(target.clone());
            }
            let (mut engine, id) = world.engine(fs.clone())?;
            let generation = count(
                &world.history()?,
                "SELECT generation FROM sources WHERE source_id = ?1",
                &[&id],
            )?;
            let mut failures = 0;
            for attempt in 0..6 {
                let report = pass(&mut engine, &id, DAY_NOW + attempt * 1000);
                assert_within_caps(&report.counters, "first failed acquisition");
                if report.failure
                    == Some(if changing {
                        FailureCode::SourceChanging
                    } else {
                        FailureCode::Io
                    })
                {
                    failures += 1;
                }
                assert_ne!(
                    report.outcome,
                    PassOutcome::Consistent,
                    "unread file is unresolved: {report:?}"
                );
                assert_eq!(
                    count(
                        &world.history()?,
                        "SELECT generation FROM sources WHERE source_id = ?1",
                        &[&id]
                    )?,
                    generation
                );
                assert_eq!(
                    count(
                        &world.history()?,
                        "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND relative_path = ?2",
                        &[&id, &relative]
                    )?,
                    0
                );
                if changing {
                    std::fs::write(&target, &bytes)?;
                    std::fs::File::open(&target)?.set_modified(modified)?;
                }
                if reopen && attempt == 2 {
                    drop(engine);
                    (engine, _) = world.engine(fs.clone())?;
                }
            }
            assert!(failures > 0, "explicit acquisition failure consumer");
            if changing {
                assert!(attempts.load(std::sync::atomic::Ordering::Relaxed) > 0);
            }
            fs.inner.on_boundary(|_, _| {});
            *fs.tail_fault.lock().map_err(|_| "fault lock")? = None;
            let recovered = drain(&mut engine, &id, DAY_NOW + 10_000, 10)?;
            assert_eq!(
                recovered
                    .iter()
                    .map(|report| report.records_committed)
                    .sum::<u32>(),
                1
            );
            assert_eq!(rows(&world.history()?, &id)?.len(), 2);
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                    &[&id]
                )?,
                8
            );
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND file_state = 'missing'",
                    &[&id]
                )?,
                0
            );
        }
    }
    Ok(())
}

fn completion_prefix_control(codex: bool, substituted: bool, restore_selected: bool) -> TestResult {
    for reopen in [false, true] {
        let world = World::new()?;
        let prefix = if codex { "sessions" } else { "" };
        let a = world.root.join(prefix).join("A");
        let b = world.root.join(prefix).join("B");
        let c = world
            .root
            .join(prefix)
            .join(if codex { "C" } else { "storage/message/own" });
        let d = world.root.join(if codex {
            "sessions/D"
        } else {
            "storage/message/blocked"
        });
        for path in [&a, &b, &c, &d] {
            std::fs::create_dir_all(path)?;
        }
        let unseen = if codex {
            "sessions/B/unseen.jsonl"
        } else {
            "storage/message/late/unseen.json"
        };
        // OpenCode's usage path must itself be the selected B directory.
        let b = if codex {
            b
        } else {
            world.root.join("storage/message/late")
        };
        std::fs::create_dir_all(&b)?;
        let checkpoint = c.join(if codex {
            "checkpoint.jsonl"
        } else {
            "checkpoint.json"
        });
        let blocked = d.join(if codex {
            "blocked.jsonl"
        } else {
            "blocked.json"
        });
        let fs = ReversedFs::new();
        let (mut engine, id) = reported_engine(&world, fs.clone(), codex)?;
        if substituted {
            for (name, input) in [("present", 10), ("removed", 20)] {
                std::fs::write(
                    b.join(format!("{name}.{}", if codex { "jsonl" } else { "json" })),
                    reported_bytes(codex, "late", name, input),
                )?;
            }
            drain(&mut engine, &id, DAY_NOW - 1000, 6)?;
            std::fs::remove_file(b.join(if codex {
                "removed.jsonl"
            } else {
                "removed.json"
            }))?;
            world.put(unseen, &reported_bytes(codex, "late", "unseen", 7))?;
        }
        std::fs::write(&checkpoint, reported_bytes(codex, "own", "checkpoint", 10))?;
        std::fs::write(&blocked, reported_bytes(codex, "blocked", "blocked", 0))?;
        let connection = world.history()?;
        let generation = count(
            &connection,
            "SELECT generation FROM sources WHERE source_id = ?1",
            &[&id],
        )?;
        let ordering = if substituted {
            vec![b.clone(), c.clone(), a.clone(), d.clone()]
        } else {
            vec![a.clone(), c.clone(), b.clone(), d.clone()]
        };
        for (ordinal, path) in ordering.iter().enumerate() {
            let relative = path
                .strip_prefix(&world.root)?
                .to_str()
                .ok_or("queue path")?;
            connection.execute("INSERT INTO frontier_directories(source_id, generation, relative_path, depth, ordinal, restart_blocked) VALUES(?1, ?2, ?3, ?4, ?5, 0)", rusqlite::params![id, generation, relative, path.strip_prefix(&world.root)?.components().count() as i64, ordinal as i64])?;
        }
        let stamp = independent_stamp(&world.root)?;
        connection.execute("INSERT INTO metadata_spool(source_id, generation, relative_path, device, inode, size, mtime_ns, parser_kind) VALUES(?1, ?2, '', ?3, ?4, ?5, ?6, 'directory')", rusqlite::params![id, generation, stamp.0 as i64, stamp.1 as i64, stamp.2 as i64, stamp.3])?;
        drop(connection);
        drop(engine);
        let (mut engine, _) = reported_engine(&world, fs.clone(), codex)?;
        let blocked_target = blocked.clone();
        let saved = world._directory.path().join("saved-B");
        // Refuse root proof only at the later entry, after the successful file checkpoint.
        *fs.budget_at_file.lock().map_err(|_| "budget lock")? =
            Some((blocked_target, world.root.clone()));
        // The acquisition hook arms no budget itself; it only records the selected-directory substitution.
        let selected = b.clone();
        let moved = saved.clone();
        fs.inner.on_boundary(move |kind, path| {
            if substituted
                && kind == quotern_core::ingest::fs::OpenKind::Directory
                && path == selected
            {
                std::fs::rename(&selected, &moved).expect("save selected B");
                std::fs::create_dir(&selected).expect("substitute empty B");
            }
        });
        let report = pass(&mut engine, &id, DAY_NOW);
        fs.inner.on_boundary(|_, _| {});
        assert_eq!(
            report.outcome,
            PassOutcome::CatchingUp,
            "{codex}/{substituted}: {report:?}"
        );
        assert!(
            report.records_committed > 0,
            "real checkpoint acquired and published: {report:?}"
        );
        assert_eq!(report.counters.stat_calls, 40_000);
        let connection = world.history()?;
        assert_eq!(
            count(
                &connection,
                "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND file_state = 'missing'",
                &[&id]
            )?,
            0,
            "refused acquisition cannot mark history missing"
        );
        let b_relative = b.strip_prefix(&world.root)?.to_str().ok_or("B relative")?;
        assert_eq!(
            count(
                &connection,
                "SELECT COUNT(*) FROM metadata_spool WHERE source_id = ?1 AND relative_path = ?2 AND parser_kind = 'directory'",
                &[&id, &b_relative]
            )?,
            0,
            "B has no selected acquisition proof"
        );
        if !substituted {
            let a_relative = a.strip_prefix(&world.root)?.to_str().ok_or("A relative")?;
            assert_eq!(
                count(
                    &connection,
                    "SELECT COUNT(*) FROM metadata_spool WHERE source_id = ?1 AND relative_path = ?2 AND parser_kind = 'directory'",
                    &[&id, &a_relative]
                )?,
                1,
                "verified completion prefix survives"
            );
            world.put(unseen, &reported_bytes(codex, "late", "unseen", 7))?;
        } else if restore_selected {
            std::fs::remove_dir(&b)?;
            std::fs::rename(saved, &b)?;
        } else {
            std::fs::write(
                b.join(if codex {
                    "present.jsonl"
                } else {
                    "present.json"
                }),
                reported_bytes(codex, "late", "present", 13),
            )?;
        }
        let a_listings = fs.listings_of(&a);
        *fs.metadata_budget.lock().map_err(|_| "budget lock")? = None;
        *fs.budget_at_file.lock().map_err(|_| "budget lock")? = None;
        if reopen {
            drop(engine);
            (engine, _) = reported_engine(&world, fs.clone(), codex)?;
        }
        drain(&mut engine, &id, DAY_NOW + 1000, 10)?;
        assert_eq!(
            count(
                &connection,
                "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                &[&id]
            )?,
            if substituted {
                if restore_selected { 47 } else { 43 }
            } else {
                17
            }
        );
        assert_eq!(
            count(
                &connection,
                "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND file_state = 'missing'",
                &[&id]
            )?,
            if substituted { 1 } else { 0 }
        );
        if !substituted {
            assert_eq!(
                fs.listings_of(&a),
                a_listings,
                "verified A never relisted during recovery"
            );
        }
        assert!(fs.listings_of(&b) >= 2);
    }
    Ok(())
}

#[test]
fn codex_selected_directory_substitution_cannot_certify_completion() -> TestResult {
    completion_prefix_control(true, true, true)
}
#[test]
fn opencode_selected_directory_substitution_cannot_certify_completion() -> TestResult {
    completion_prefix_control(false, true, true)
}
#[test]
fn codex_verified_completion_prefix_survives_later_proof_refusal() -> TestResult {
    completion_prefix_control(true, false, true)
}
#[test]
fn opencode_verified_completion_prefix_survives_later_proof_refusal() -> TestResult {
    completion_prefix_control(false, false, true)
}

#[test]
fn stable_child_directory_replacement_reselects_and_drains() -> TestResult {
    completion_prefix_control(true, true, false)?;
    completion_prefix_control(false, true, false)
}

#[test]
fn selected_part_directory_substitution_is_not_absent_parts() -> TestResult {
    for prune in [false, true] {
        for reopen in [false, true] {
            let world = World::new()?;
            world.put(
                &reported_path(false, "present"),
                &reported_bytes(false, "own", "present", 10),
            )?;
            let fs = ReversedFs::new();
            let (mut engine, id) = reported_engine(&world, fs.clone(), false)?;
            drain(&mut engine, &id, DAY_NOW, 4)?;
            world.put(
                &reported_path(false, "z-new"),
                &reported_bytes(false, "own", "z-new", 7),
            )?;
            let target = world.root.join("storage/part/z-new");
            let saved = world._directory.path().join("saved-parts");
            std::fs::create_dir_all(&target)?;
            let selected = target.clone();
            let moved = saved.clone();
            let message = world.root.join(reported_path(false, "z-new"));
            let mut acquired_parent = false;
            let mut changed = false;
            fs.inner.on_boundary(move |kind, path| {
                if kind == quotern_core::ingest::fs::OpenKind::Bounded && path == message {
                    acquired_parent = true;
                }
                if acquired_parent
                    && !changed
                    && kind == quotern_core::ingest::fs::OpenKind::Directory
                    && path == selected
                {
                    changed = true;
                    std::fs::rename(&selected, &moved).expect("move selected part directory");
                    if !prune {
                        std::fs::create_dir(&selected).expect("substitute empty parts");
                    }
                }
            });
            let report = pass(&mut engine, &id, DAY_NOW + 1000);
            fs.inner.on_boundary(|_, _| {});
            let connection = world.history()?;
            if prune {
                assert_eq!(
                    report.outcome,
                    PassOutcome::Consistent,
                    "independently confirmed pruning: {report:?}"
                );
                assert_eq!(
                    count(
                        &connection,
                        "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                        &[&id]
                    )?,
                    17
                );
            } else {
                assert_eq!(
                    report.failure,
                    Some(FailureCode::SourceChanging),
                    "selected parts differ: {report:?}"
                );
                assert_eq!(
                    count(
                        &connection,
                        "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                        &[&id]
                    )?,
                    10,
                    "no false absent-parts publication"
                );
                std::fs::remove_dir(&target)?;
            }
            std::fs::rename(saved, &target)?;
            if reopen {
                drop(engine);
                (engine, _) = reported_engine(&world, fs.clone(), false)?;
            }
            drain(&mut engine, &id, DAY_NOW + 2000, 8)?;
            assert_eq!(
                count(
                    &connection,
                    "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                    &[&id]
                )?,
                17
            );
            assert_eq!(
                count(
                    &connection,
                    "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND file_state = 'missing'",
                    &[&id]
                )?,
                0
            );
        }
    }
    Ok(())
}

struct SelectedFs<R>(R);

impl<R: Fn(&Path, &mut PassCounters) -> io::Result<DirEntries>> SourceFs for SelectedFs<R> {
    fn canonicalize(&self, path: &Path, counters: &mut PassCounters) -> io::Result<PathBuf> {
        RealSourceFs.canonicalize(path, counters)
    }
    fn metadata(&self, path: &Path, counters: &mut PassCounters) -> io::Result<std::fs::Metadata> {
        RealSourceFs.metadata(path, counters)
    }
    fn read_dir(&self, path: &Path, counters: &mut PassCounters) -> io::Result<DirEntries> {
        (self.0)(path, counters)
    }
    fn read_header(&self, path: &Path, counters: &mut PassCounters) -> io::Result<Vec<u8>> {
        RealSourceFs.read_header(path, counters)
    }
    fn read_bounded(
        &self,
        path: &Path,
        max: usize,
        counters: &mut PassCounters,
    ) -> io::Result<BoundedRead> {
        RealSourceFs.read_bounded(path, max, counters)
    }
    fn read_tail(
        &self,
        path: &Path,
        offset: u64,
        max: usize,
        counters: &mut PassCounters,
    ) -> io::Result<BoundedRead> {
        RealSourceFs.read_tail(path, offset, max, counters)
    }

    fn open_sqlite(&self, path: &Path) -> Result<Connection, OpenError> {
        RealSourceFs.open_sqlite(path)
    }
}

fn empty_listing() -> DirEntries {
    Box::new(std::iter::empty())
}

#[test]
fn selected_directory_native_and_lazy_delegation_preserve_exact_work() -> TestResult {
    let world = World::new()?;
    world.put("entry", b"")?;
    let stamp = FileStamp::of(&std::fs::metadata(&world.root)?);
    let mut ordinary = PassCounters::default();
    let before = physical_operations();
    let entries = RealSourceFs.read_dir(&world.root, &mut ordinary)?;
    assert_eq!(
        entries.collect::<io::Result<Vec<_>>>()?,
        vec![world.root.join("entry")]
    );
    let metadata = physical_operations().metadata - before.metadata;
    assert_eq!(u64::from(ordinary.stat_calls), metadata);
    for recording in [false, true] {
        let fs = RecordingFs::new();
        let delegated =
            SelectedFs(|path: &Path, counters: &mut PassCounters| fs.read_dir(path, counters));
        let mut counters = PassCounters::default();
        let before = physical_operations();
        let entries = if recording {
            delegated.read_dir_selected(&world.root, stamp, &mut counters)?
        } else {
            RealSourceFs.read_dir_selected(&world.root, stamp, &mut counters)?
        };
        assert_eq!(
            entries.collect::<io::Result<Vec<_>>>()?,
            vec![world.root.join("entry")]
        );
        let after = physical_operations();
        assert_eq!(u64::from(counters.stat_calls), metadata);
        assert_eq!(after.metadata - before.metadata, metadata);
        assert_eq!(after.directory_opens - before.directory_opens, 1);
        assert_eq!(after.directory_yields - before.directory_yields, 1);
        assert_eq!(fs.metrics().open_directories, 0);
    }
    let unsupported = SelectedFs(|_: &Path, _: &mut PassCounters| Ok(empty_listing()));
    let mut counters = PassCounters::default();
    let before = physical_operations();
    assert_eq!(
        unsupported
            .read_dir_selected(&world.root, stamp, &mut counters)
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::Unsupported
    );
    assert_eq!(counters, PassCounters::default());
    assert_eq!(physical_operations(), before);
    Ok(())
}

fn nested_selected(
    path: &Path,
    stamp: FileStamp,
    depth: usize,
    counters: &mut PassCounters,
) -> io::Result<DirEntries> {
    SelectedFs(|path: &Path, counters: &mut PassCounters| {
        if depth == 0 {
            Ok(empty_listing())
        } else {
            nested_selected(path, stamp, depth - 1, counters)
        }
    })
    .read_dir_selected(path, stamp, counters)
}

#[test]
fn selected_directory_scope_limits_refuse_before_provider_work() -> TestResult {
    use std::os::unix::ffi::OsStringExt;
    let world = World::new()?;
    let stamp = FileStamp::of(&std::fs::metadata(&world.root)?);
    let mut counters = PassCounters::default();
    let before = physical_operations();
    let error = nested_selected(&world.root, stamp, 8, &mut counters)
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert_eq!(error.to_string(), "selected directory scope limit exceeded");
    assert_eq!(
        nested_selected(&world.root, stamp, 7, &mut counters)
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::Unsupported
    );
    let called = std::cell::Cell::new(0);
    let provider = SelectedFs(|_: &Path, _: &mut PassCounters| {
        called.set(called.get() + 1);
        Ok(empty_listing())
    });
    let paths = [
        PathBuf::from("relative"),
        PathBuf::from("/a\0b"),
        PathBuf::from("/a/../b"),
        PathBuf::from("/a/./b"),
        PathBuf::from("/a//b"),
        PathBuf::from(format!("/{}", "a".repeat(4096))),
        PathBuf::from(std::ffi::OsString::from_vec(vec![b'/', 0xff])),
    ];
    for path in paths {
        let error = provider
            .read_dir_selected(&path, stamp, &mut counters)
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }
    assert_eq!(called.get(), 0);
    let boundary = PathBuf::from(format!("/{}", "a".repeat(4095)));
    assert_eq!(
        provider
            .read_dir_selected(&boundary, stamp, &mut counters)
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::Unsupported
    );
    assert_eq!(called.get(), 1);
    assert_eq!(counters, PassCounters::default());
    assert_eq!(physical_operations(), before);
    // The refused ninth scope leaves all eight outer scopes restored.
    drop(RealSourceFs.read_dir_selected(&world.root, stamp, &mut counters)?);
    Ok(())
}

#[test]
fn selected_directory_nested_thread_and_wrong_path_cannot_supply_outer_proof() -> TestResult {
    let world = World::new()?;
    let other = world.root.join("other");
    std::fs::create_dir(&other)?;
    let stamp = FileStamp::of(&std::fs::metadata(&world.root)?);
    let inner = SelectedFs(|path: &Path, counters: &mut PassCounters| {
        drop(RealSourceFs.read_dir_selected(path, stamp, counters)?);
        Ok(empty_listing())
    });
    let wrong = SelectedFs(|_: &Path, counters: &mut PassCounters| {
        drop(RealSourceFs.read_dir(&other, counters)?);
        Ok(empty_listing())
    });
    let threaded = SelectedFs(|path: &Path, _: &mut PassCounters| {
        let path = path.to_path_buf();
        std::thread::spawn(move || {
            let mut counters = PassCounters::default();
            drop(
                RealSourceFs
                    .read_dir_selected(&path, stamp, &mut counters)
                    .unwrap(),
            );
        })
        .join()
        .unwrap();
        Ok(empty_listing())
    });
    for provider in [&inner as &dyn SourceFs, &wrong, &threaded] {
        let mut counters = PassCounters::default();
        assert_eq!(
            provider
                .read_dir_selected(&world.root, stamp, &mut counters)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::Unsupported
        );
    }
    let ordinary_threaded = SelectedFs(|path: &Path, _: &mut PassCounters| {
        let path = path.to_path_buf();
        std::thread::spawn(move || {
            drop(
                RealSourceFs
                    .read_dir(&path, &mut PassCounters::default())
                    .unwrap(),
            );
        })
        .join()
        .unwrap();
        Ok(empty_listing())
    });
    assert_eq!(
        ordinary_threaded
            .read_dir_selected(&world.root, stamp, &mut PassCounters::default())
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::Unsupported
    );
    let outer = SelectedFs(|path: &Path, counters: &mut PassCounters| {
        drop(RealSourceFs.read_dir_selected(path, stamp, counters)?);
        RealSourceFs.read_dir(path, counters)
    });
    drop(outer.read_dir_selected(&world.root, stamp, &mut PassCounters::default())?);
    Ok(())
}

#[test]
fn selected_directory_failed_attempt_and_unwind_clear_prior_proof() -> TestResult {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    let world = World::new()?;
    let stamp = FileStamp::of(&std::fs::metadata(&world.root)?);
    let saved = world.root.with_extension("saved");
    let failed = SelectedFs(|path: &Path, counters: &mut PassCounters| {
        let entries = RealSourceFs.read_dir(path, counters)?;
        std::fs::rename(path, &saved)?;
        assert_eq!(
            RealSourceFs.read_dir(path, counters).err().unwrap().kind(),
            io::ErrorKind::NotFound
        );
        std::fs::rename(&saved, path)?;
        Ok(entries)
    });
    let mut counters = PassCounters::default();
    let before = physical_operations();
    assert_eq!(
        failed
            .read_dir_selected(&world.root, stamp, &mut counters)
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::Unsupported
    );
    assert_eq!(
        physical_operations().metadata - before.metadata,
        u64::from(counters.stat_calls)
    );
    let recorder = RecordingFs::new();
    let panicked = SelectedFs(|path: &Path, counters: &mut PassCounters| {
        let entries = recorder.read_dir(path, counters)?;
        recorder.on_boundary(|_, _| panic!("directory acquisition boundary"));
        assert!(catch_unwind(AssertUnwindSafe(|| recorder.read_dir(path, counters))).is_err());
        Ok(entries)
    });
    assert_eq!(
        panicked
            .read_dir_selected(&world.root, stamp, &mut PassCounters::default())
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::Unsupported
    );
    assert_eq!(recorder.metrics().open_directories, 0);
    let unwind = SelectedFs(|_: &Path, _: &mut PassCounters| -> io::Result<DirEntries> {
        panic!("scope unwind")
    });
    assert!(
        catch_unwind(AssertUnwindSafe(|| unwind.read_dir_selected(
            &world.root,
            stamp,
            &mut PassCounters::default()
        )))
        .is_err()
    );
    drop(RealSourceFs.read_dir_selected(&world.root, stamp, &mut PassCounters::default())?);
    let nested = SelectedFs(|path: &Path, counters: &mut PassCounters| {
        let entries = RealSourceFs.read_dir(path, counters)?;
        assert!(
            catch_unwind(AssertUnwindSafe(
                || unwind.read_dir_selected(path, stamp, counters)
            ))
            .is_err()
        );
        Ok(entries)
    });
    drop(nested.read_dir_selected(&world.root, stamp, &mut PassCounters::default())?);
    Ok(())
}

#[test]
fn dated_selected_directory_substitution_rejects_populated_foreign_history() -> TestResult {
    for reopen in [false, true] {
        let world = World::new()?;
        world.put(
            "sessions/2026/03/29/own.jsonl",
            &reported_bytes(true, "own", "own", 3),
        )?;
        let dated = world.root.join("sessions/2026/03/29");
        let saved = world.root.join("saved");
        let foreign = world.root.join("foreign");
        std::fs::create_dir(&foreign)?;
        std::fs::write(
            foreign.join("hostile.jsonl"),
            reported_bytes(true, "foreign", "hostile", 7),
        )?;
        let fs = RecordingFs::new();
        let target = dated.clone();
        let moved = saved.clone();
        let substituted = foreign.clone();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let trace = Arc::clone(&calls);
        let recording = fs.clone();
        let root = world.root.clone();
        let provider = SelectedFs(move |path: &Path, counters: &mut PassCounters| {
            if path == target && trace.fetch_add(1, std::sync::atomic::Ordering::Relaxed) == 0 {
                std::fs::rename(&target, &moved)?;
                std::fs::rename(&substituted, &target)?;
                recording.read_dir(path, counters)
            } else {
                if path == root && moved.exists() {
                    std::fs::rename(&target, &substituted)?;
                    std::fs::rename(&moved, &target)?;
                }
                recording.read_dir(path, counters)
            }
        });
        let (mut engine, id) = world.engine(provider)?;
        let report = pass(&mut engine, &id, DAY_NOW);
        assert!(calls.load(std::sync::atomic::Ordering::Relaxed) > 0);
        assert_eq!(
            report.failure,
            Some(FailureCode::SourceChanging),
            "{report:?}"
        );
        assert_within_caps(&report.counters, "dated replacement");
        let encoded = serde_json::to_value(
            engine
                .today_snapshot("UTC", DAY_NOW)
                .map_err(|e| format!("{e:?}"))?,
        )?;
        assert_eq!(encoded["source_reported"][0]["records"], 1);
        assert_eq!(encoded["source_reported"][0]["input"]["value"], 3);
        assert_eq!(
            count(
                &world.history()?,
                "SELECT COUNT(*) FROM usage_events WHERE source_id = ?1 AND message_id = ?2",
                &[&id, &"hostile"]
            )?,
            0
        );
        if reopen {
            drop(engine);
            let (mut reopened, _) = world.engine(RealSourceFs)?;
            drain(&mut reopened, &id, DAY_NOW + 1000, 8)?;
            assert_eq!(
                pass(&mut reopened, &id, DAY_NOW + 20_000).records_committed,
                0
            );
            let encoded = serde_json::to_value(
                reopened
                    .today_snapshot("UTC", DAY_NOW + 1000)
                    .map_err(|e| format!("{e:?}"))?,
            )?;
            assert_eq!(encoded["source_reported"][0]["input"]["value"], 3);
        } else {
            drain(&mut engine, &id, DAY_NOW + 1000, 8)?;
        }
        let actual = rows(&world.history()?, &id)?;
        assert_eq!(actual.len(), 1);
        assert_eq!(actual[0]["response_id"], "own");
        assert_eq!(actual[0]["input_tokens"], 3);
        assert!(fs.metrics().max_open_directories <= 8);
    }
    Ok(())
}

#[test]
fn dated_descriptor_validation_budget_keeps_last_good_after_publication() -> TestResult {
    for ceiling in [39_999, 40_000] {
        for reopen in [false, true] {
            let world = World::new()?;
            let present = "sessions/old/present.jsonl";
            world.put(present, &reported_bytes(true, "own", "present", 10))?;
            std::fs::create_dir_all(world.root.join("sessions/2026/03/29"))?;
            let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let blocked = world.root.join("sessions/2026/03/29");
            let mode = Arc::clone(&armed);
            let fs = SelectedFs(move |path: &Path, counters: &mut PassCounters| {
                if path == blocked && mode.load(std::sync::atomic::Ordering::Relaxed) {
                    while counters.stat_calls < ceiling {
                        RealSourceFs.metadata(path, counters)?;
                    }
                }
                RealSourceFs.read_dir(path, counters)
            });
            let (mut engine, id) = world.engine(fs)?;
            drain(&mut engine, &id, DAY_NOW, 8)?;
            let last_good = count(
                &world.history()?,
                "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
                &[&id],
            )?;
            world.put(present, &reported_bytes(true, "own", "present", 11))?;
            armed.store(true, std::sync::atomic::Ordering::Relaxed);
            let before = physical_operations();
            let report = pass(&mut engine, &id, DAY_NOW + 1000);
            assert_eq!(report.records_committed, 1, "positive publication");
            assert_eq!(report.outcome, PassOutcome::CatchingUp);
            assert_eq!(report.counters.stat_calls, 40_000);
            assert_eq!(physical_operations().metadata - before.metadata, 40_000);
            assert_eq!(
                report.last_good_ms,
                Some(last_good),
                "validation refusal: {report:?}"
            );
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
                    &[&id]
                )?,
                last_good
            );
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                    &[&id]
                )?,
                11
            );
            armed.store(false, std::sync::atomic::Ordering::Relaxed);
            if reopen {
                drop(engine);
                let fs = SelectedFs(|path: &Path, counters: &mut PassCounters| {
                    RealSourceFs.read_dir(path, counters)
                });
                let (mut reopened, _) = world.engine(fs)?;
                let encoded = serde_json::to_value(
                    reopened
                        .today_snapshot("UTC", DAY_NOW + 1000)
                        .map_err(|e| format!("{e:?}"))?,
                )?;
                assert_eq!(
                    encoded["source_reported"][0]["input"]["last_good_ms"],
                    last_good
                );
                drain(&mut reopened, &id, DAY_NOW + 2000, 8)?;
                assert_eq!(
                    pass(&mut reopened, &id, DAY_NOW + 20_000).records_committed,
                    0
                );
            } else {
                let encoded = serde_json::to_value(
                    engine
                        .today_snapshot("UTC", DAY_NOW + 1000)
                        .map_err(|e| format!("{e:?}"))?,
                )?;
                assert_eq!(
                    encoded["source_reported"][0]["input"]["last_good_ms"],
                    last_good
                );
                drain(&mut engine, &id, DAY_NOW + 2000, 8)?;
                assert_eq!(
                    pass(&mut engine, &id, DAY_NOW + 20_000).records_committed,
                    0
                );
            }
        }
    }
    Ok(())
}

#[test]
fn failed_current_acquisition_does_not_pin_unknown_historical_sibling() -> TestResult {
    for known in [true, false] {
        for reopen in [false, true] {
            let world = World::new()?;
            let relative = if known {
                "sessions/old/z-failed.jsonl"
            } else {
                "sessions/2026/03/29/z-failed.jsonl"
            };
            let target = world.put(relative, &reported_bytes(true, "own", "failed", 5))?;
            let fs = ReversedFs::new();
            let (mut engine, id) = world.engine(fs.clone())?;
            if known {
                drain(&mut engine, &id, DAY_NOW, 8)?;
            }
            world.put(relative, &reported_bytes(true, "own", "failed", 6))?;
            world.put(
                "sessions/old/a-stable.jsonl",
                &reported_bytes(true, "own", "stable", 3),
            )?;
            *fs.tail_fault.lock().map_err(|_| "fault lock")? = Some(target.clone());
            let generation = count(
                &world.history()?,
                "SELECT generation FROM sources WHERE source_id = ?1",
                &[&id],
            )?;
            for attempt in 0..6 {
                fs.tail_attempts
                    .lock()
                    .map_err(|_| "attempts lock")?
                    .clear();
                let report = pass(&mut engine, &id, DAY_NOW + 1000 + attempt * 1000);
                assert_eq!(
                    fs.tail_attempts
                        .lock()
                        .map_err(|_| "attempts lock")?
                        .iter()
                        .filter(|path| **path == target)
                        .count(),
                    1,
                    "one failed acquisition per pass"
                );
                assert_eq!(report.failure, Some(FailureCode::Io), "{report:?}");
                assert_ne!(report.outcome, PassOutcome::Consistent);
                assert_within_caps(&report.counters, "failed current sibling");
                assert_eq!(
                    count(
                        &world.history()?,
                        "SELECT generation FROM sources WHERE source_id = ?1",
                        &[&id]
                    )?,
                    generation
                );
                if reopen && attempt == 2 {
                    drop(engine);
                    (engine, _) = world.engine(fs.clone())?;
                }
            }
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT COUNT(*) FROM usage_events WHERE source_id = ?1 AND message_id = ?2",
                    &[&id, &"stable"]
                )?,
                1,
                "stable B progresses while A remains failed"
            );
            assert!(
                count(
                    &world.history()?,
                    "SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1",
                    &[&id]
                )? > 0
            );
            *fs.tail_fault.lock().map_err(|_| "fault lock")? = None;
            let recovered = drain(&mut engine, &id, DAY_NOW + 20_000, 12)?;
            assert_eq!(
                recovered.iter().map(|r| r.records_committed).sum::<u32>(),
                1
            );
            assert_eq!(rows(&world.history()?, &id)?.len(), 2);
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                    &[&id]
                )?,
                9
            );
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND file_state = 'missing'",
                    &[&id]
                )?,
                0
            );
            assert_eq!(
                pass(&mut engine, &id, DAY_NOW + 50_000).records_committed,
                0
            );
        }
    }
    Ok(())
}

#[test]
fn cached_success_with_changed_stamp_does_not_pin_unknown_historical_sibling() -> TestResult {
    for reopen in [false, true] {
        let world = World::new()?;
        let relative = "sessions/old/z-changing.jsonl";
        let target = world.put(relative, &reported_bytes(true, "own", "changing", 5))?;
        let fs = ReversedFs::new();
        let (mut engine, id) = world.engine(fs.clone())?;
        drain(&mut engine, &id, DAY_NOW, 8)?;
        world.put(
            "sessions/old/a-stable.jsonl",
            &reported_bytes(true, "own", "stable", 3),
        )?;
        let root = world.root.join("sessions/old");
        let mut value = 5;
        fs.inner.on_boundary(move |kind, path| {
            if kind == quotern_core::ingest::fs::OpenKind::Directory && path == root {
                value += 1;
                std::fs::write(&target, reported_bytes(true, "own", "changing", value))
                    .expect("change between lane lookups");
            }
        });
        for attempt in 0..4 {
            let report = pass(&mut engine, &id, DAY_NOW + 1000 + attempt * 1000);
            assert_eq!(report.outcome, PassOutcome::CatchingUp);
            assert_eq!(
                report.failure, None,
                "successful cached selection remains unfinished"
            );
            assert_within_caps(&report.counters, "cached changed stamp");
            assert!(
                report.counters.stat_calls < 40_000,
                "historical reserve remains available"
            );
            assert_eq!(
                count(
                    &world.history()?,
                    "SELECT COUNT(*) FROM usage_events WHERE source_id = ?1 AND message_id = ?2",
                    &[&id, &"stable"]
                )?,
                1,
                "B progresses while A changes between lanes"
            );
            assert!(
                count(
                    &world.history()?,
                    "SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1",
                    &[&id]
                )? > 0
            );
            if reopen && attempt == 1 {
                drop(engine);
                (engine, _) = world.engine(fs.clone())?;
            }
        }
        fs.inner.on_boundary(|_, _| {});
        drain(&mut engine, &id, DAY_NOW + 20_000, 8)?;
        assert_eq!(rows(&world.history()?, &id)?.len(), 2);
        assert_eq!(
            count(
                &world.history()?,
                "SELECT SUM(input_tokens) FROM usage_events WHERE source_id = ?1",
                &[&id]
            )?,
            12
        );
        assert_eq!(
            pass(&mut engine, &id, DAY_NOW + 50_000).records_committed,
            0
        );
    }
    Ok(())
}

#[derive(Clone)]
struct CurrentBudgetFs {
    inner: RecordingFs,
    target: PathBuf,
    a_first: bool,
    armed: Arc<Mutex<bool>>,
    selections: Arc<Mutex<Vec<(PathBuf, u32)>>>,
}

impl SourceFs for CurrentBudgetFs {
    fn canonicalize(&self, path: &Path, counters: &mut PassCounters) -> io::Result<PathBuf> {
        self.inner.canonicalize(path, counters)
    }

    fn metadata(&self, path: &Path, counters: &mut PassCounters) -> io::Result<std::fs::Metadata> {
        if path == self.target
            && *self
                .armed
                .lock()
                .map_err(|_| io::Error::other("budget lock"))?
            && counters.stat_calls < 20_000
        {
            while counters.stat_calls < 19_999 {
                self.inner.metadata(path, counters)?;
            }
        }
        let metadata = self.inner.metadata(path, counters)?;
        self.selections
            .lock()
            .map_err(|_| io::Error::other("selection lock"))?
            .push((path.to_path_buf(), counters.stat_calls));
        Ok(metadata)
    }

    fn read_dir(&self, path: &Path, counters: &mut PassCounters) -> io::Result<DirEntries> {
        let entries = self.inner.read_dir(path, counters)?;
        if self.target.parent() != Some(path) {
            return Ok(entries);
        }
        // Eager ordering of this two-entry fixture proves semantics, not native listing laziness.
        let mut entries: Vec<_> = entries.take(3).collect();
        assert!(entries.len() <= 2, "two-entry ordering fixture");
        entries.sort_by_key(|entry| {
            entry
                .as_ref()
                .map(|path| (path == &self.target) != self.a_first)
                .unwrap_or(true)
        });
        Ok(Box::new(entries.into_iter()))
    }

    fn read_header(&self, path: &Path, counters: &mut PassCounters) -> io::Result<Vec<u8>> {
        self.inner.read_header(path, counters)
    }

    fn read_bounded(
        &self,
        path: &Path,
        max: usize,
        counters: &mut PassCounters,
    ) -> io::Result<BoundedRead> {
        self.inner.read_bounded(path, max, counters)
    }

    fn read_tail(
        &self,
        path: &Path,
        offset: u64,
        max: usize,
        counters: &mut PassCounters,
    ) -> io::Result<BoundedRead> {
        self.inner.read_tail(path, offset, max, counters)
    }

    fn open_sqlite(&self, path: &Path) -> Result<Connection, OpenError> {
        self.inner.open_sqlite(path)
    }
}

#[test]
fn cached_current_metadata_budget_does_not_pin_unknown_historical_sibling() -> TestResult {
    for (a_first, reopen) in [(true, false), (true, true), (false, false), (false, true)] {
        let world = World::new()?;
        let relative = "sessions/a-known.jsonl";
        let target = world.put(relative, &reported_bytes(true, "own", "changing", 5))?;
        let fs = CurrentBudgetFs {
            inner: RecordingFs::new(),
            target: target.clone(),
            a_first,
            armed: Arc::new(Mutex::new(false)),
            selections: Arc::new(Mutex::new(Vec::new())),
        };
        let (mut engine, id) = world.engine(fs.clone())?;
        drain(&mut engine, &id, DAY_NOW, 8)?;
        let old_state = file_state(&world.history()?, &id, relative)?;
        let generation = count(
            &world.history()?,
            "SELECT generation FROM sources WHERE source_id = ?1",
            &[&id],
        )?;
        let changed = reported_bytes(true, "own", "changing", 60);
        world.put(relative, &changed)?;
        // Keeping B beside A avoids a retry-parent EOF between their historical visits.
        let sibling_relative = "sessions/b-unknown.jsonl";
        let sibling_bytes = reported_bytes(true, "own", "stable", 3);
        let sibling = world.put(sibling_relative, &sibling_bytes)?;
        assert_eq!(
            count(
                &world.history()?,
                "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND relative_path = ?2",
                &[&id, &sibling_relative]
            )?,
            0
        );
        *fs.armed.lock().map_err(|_| "budget lock")? = true;
        let acquisitions = Arc::new(Mutex::new(Vec::new()));
        let attempts = Arc::clone(&acquisitions);
        fs.inner.on_boundary(move |kind, path| {
            if kind == quotern_core::ingest::fs::OpenKind::Tail {
                attempts
                    .lock()
                    .expect("acquisition lock")
                    .push(path.to_path_buf());
            }
        });
        for attempt in 0..3 {
            fs.selections.lock().map_err(|_| "selection lock")?.clear();
            acquisitions.lock().map_err(|_| "acquisition lock")?.clear();
            let before = physical_operations();
            let metrics = fs.inner.metrics();
            let report = pass(&mut engine, &id, DAY_NOW + 1000 + attempt * 1000);
            let after = physical_operations();
            assert_eq!(report.records_committed, u32::from(attempt == 0));
            let selections = fs.selections.lock().map_err(|_| "selection lock")?;
            let a: Vec<_> = selections
                .iter()
                .filter(|(path, _)| *path == target)
                .collect();
            assert_eq!(
                a.len(),
                2,
                "one Current selection and one cached historical selection"
            );
            assert_eq!(a[0].1, 20_000, "selection succeeds at the Current ceiling");
            assert!(a[1].1 > 20_000 && a[1].1 < 40_000);
            if attempt == 0 {
                let a_index = selections
                    .iter()
                    .rposition(|(path, _)| *path == target)
                    .ok_or("A selection")?;
                let b_index = selections
                    .iter()
                    .position(|(path, _)| *path == sibling)
                    .ok_or("B selection")?;
                assert_eq!(
                    a_index < b_index,
                    a_first,
                    "controlled historical order: A-first={a_first}, reopen={reopen}"
                );
            }
            drop(selections);
            let attempts = acquisitions.lock().map_err(|_| "acquisition lock")?;
            assert_eq!(
                attempts.iter().filter(|path| **path == target).count(),
                0,
                "ordinary Budget is cached before content acquisition, with no same-pass retry"
            );
            assert_eq!(
                attempts.iter().filter(|path| **path == sibling).count(),
                usize::from(attempt == 0)
            );
            drop(attempts);
            assert_eq!(report.outcome, PassOutcome::CatchingUp, "{report:?}");
            assert_eq!(report.failure, None, "no descriptor-validation refusal");
            assert_within_caps(&report.counters, "cached Current budget");
            assert!(
                report.counters.stat_calls > 20_000 && report.counters.stat_calls < 40_000,
                "genuine Full reserve remains: {report:?}"
            );
            assert_eq!(
                after.metadata - before.metadata,
                u64::from(report.counters.stat_calls)
            );
            assert_eq!(
                fs.inner.metrics().stat_calls - metrics.stat_calls,
                after.metadata - before.metadata
            );
            assert_eq!(
                fs.inner.metrics().entries - metrics.entries,
                u64::from(report.counters.entries)
            );
            assert!(fs.inner.metrics().max_open_directories <= 8);
            assert_eq!(report.counters.header_reads, u32::from(attempt == 0));
            assert_eq!(
                report.counters.bytes_read,
                if attempt == 0 {
                    sibling_bytes.len() as u64
                } else {
                    0
                }
            );
            let connection = world.history()?;
            let actual = rows(&connection, &id)?;
            assert_eq!(actual.len(), 2, "unknown B publishes during this same pass");
            assert_eq!(actual[0]["response_id"], "stable");
            assert_eq!(actual[0]["input_tokens"], 3);
            assert_eq!(actual[0]["revision"], 1);
            assert_eq!(actual[1]["response_id"], "changing");
            assert_eq!(
                actual[1]["input_tokens"], 5,
                "A retains its committed history"
            );
            assert_eq!(actual[1]["revision"], 1);
            assert_eq!(file_state(&connection, &id, relative)?, old_state);
            assert_eq!(
                count(
                    &connection,
                    "SELECT generation FROM sources WHERE source_id = ?1",
                    &[&id]
                )?,
                generation
            );
            assert_eq!(
                count(
                    &connection,
                    "SELECT dirty FROM sources WHERE source_id = ?1",
                    &[&id]
                )?,
                1
            );
            assert_eq!(
                count(
                    &connection,
                    "SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1 AND relative_path = 'sessions'",
                    &[&id]
                )?,
                1,
                "A's owning parent retains durable retry work"
            );
            assert_eq!(
                count(
                    &connection,
                    "SELECT COUNT(*) FROM source_files WHERE source_id = ?1 AND file_state = 'missing'",
                    &[&id]
                )?,
                0
            );
            let snapshot = serde_json::to_value(
                engine
                    .today_snapshot("UTC", DAY_NOW + 4000)
                    .map_err(|error| format!("{error:?}"))?,
            )?;
            let input = &snapshot["source_reported"][0]["input"];
            assert_eq!(input["value"], 8);
            assert_eq!(input["status"], "catching_up");
            assert_eq!(input["completeness"], "complete");
            assert_eq!(
                snapshot["source_reported"][0]["cache_write"]["value"],
                Value::Null
            );
            if reopen && attempt == 0 {
                drop(engine);
                (engine, _) = world.engine(fs.clone())?;
            }
        }
        *fs.armed.lock().map_err(|_| "budget lock")? = false;
        let before_recovery = physical_operations();
        let recovered = drain(&mut engine, &id, DAY_NOW + 20_000, 8)?;
        assert_eq!(
            physical_operations().metadata - before_recovery.metadata,
            recovered
                .iter()
                .map(|report| u64::from(report.counters.stat_calls))
                .sum::<u64>()
        );
        for report in &recovered {
            assert_within_caps(&report.counters, "Current budget recovery");
            assert_eq!(report.failure, None);
        }
        assert_eq!(
            recovered
                .iter()
                .map(|report| report.records_committed)
                .sum::<u32>(),
            1
        );
        let connection = world.history()?;
        let actual = rows(&connection, &id)?;
        assert_eq!(actual.len(), 2);
        assert_eq!(actual[0]["response_id"], "stable");
        assert_eq!(actual[0]["input_tokens"], 3);
        assert_eq!(actual[0]["total_tokens"], 3);
        assert_eq!(actual[0]["revision"], 1);
        assert_eq!(actual[1]["response_id"], "changing");
        assert_eq!(actual[1]["input_tokens"], 60);
        assert_eq!(actual[1]["total_tokens"], 60);
        assert_eq!(actual[1]["revision"], 2);
        assert_eq!(
            file_state(&connection, &id, relative)?,
            (changed.len() as i64, None, "present".into())
        );
        let mut statement = connection.prepare("SELECT relative_path, file_state FROM source_files WHERE source_id = ?1 AND adapter_state = 'codex_jsonl' ORDER BY relative_path")?;
        let membership = statement
            .query_map([&id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            membership,
            vec![
                (relative.into(), "present".into()),
                (sibling_relative.into(), "present".into())
            ]
        );
        assert_eq!(
            count(
                &connection,
                "SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1",
                &[&id]
            )?,
            0
        );
        let snapshot = serde_json::to_value(
            engine
                .today_snapshot(
                    "UTC",
                    recovered
                        .last()
                        .ok_or("recovery report")?
                        .last_good_ms
                        .ok_or("recovery freshness")?,
                )
                .map_err(|error| format!("{error:?}"))?,
        )?;
        assert_eq!(snapshot["source_reported"][0]["input"]["value"], 63);
        assert_eq!(snapshot["source_reported"][0]["input"]["status"], "current");
        assert_eq!(
            snapshot["source_reported"][0]["input"]["completeness"],
            "complete"
        );
        let replay = pass(&mut engine, &id, DAY_NOW + 600_000);
        assert_eq!(replay.outcome, PassOutcome::Consistent);
        assert_eq!(replay.records_committed, 0);
        assert_eq!(replay.counters.bytes_read, 0);
        assert_eq!(rows(&world.history()?, &id)?, actual);
    }
    Ok(())
}
