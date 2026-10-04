pub mod migrations;

use std::collections::BTreeSet;
use std::fs::{File, Metadata};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::discovery::DataAnchor;
use crate::domain::{
    AcquisitionConsistency, ConsentState, FailureCode, OPENCODE_SOURCE_CONVENTION,
    ObservationStatus, OriginUncertainty, PassCounters, PassOutcome, ProjectionConsistency,
    Provenance, RecordCandidate, SourceKind, SourceReportedObservation, TokenComponents,
    TokenObservation, TokenUnit, is_valid_id_component, required_nullable, total_metadata_is_valid,
};
use crate::ingest::sqlite_ro::{self, with_rollback_view};
use crate::limits::{
    MAX_FAILED_FILES, MAX_METADATA_SPOOL_BYTES, MAX_METADATA_SPOOL_ROWS, MAX_OBSERVATION_PAGE,
    MAX_PATH_BYTES, MAX_PROGRESS_CURSOR_BYTES, MAX_RECORD_ID_BYTES, MAX_SELECTED_PART_IDS,
    MAX_SOURCE_TIMESTAMP_MS, MAX_TOKEN_COUNT, RETRY_INITIAL_MS, RETRY_MAX_MS,
    SOURCE_CHANGING_RETRIES,
};
use crate::snapshot::{ObservationCursor, ObservationPage, SourceProjection};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(feature = "test-faults")]
pub enum FaultPoint {
    BeforeCommit,
    AfterCommit,
}

#[derive(Debug, Eq, PartialEq)]
pub enum StoreError {
    Io,
    Sqlite,
    CountOutOfRange,
    InvalidRoot,
    InvalidRelativePath,
    InvalidStoredValue,
    LimitExceeded,
    /// History file or sidecar is a symlink, hard link or non-regular file, or was replaced.
    UnsafeFile,
    /// An existing history database was written by a newer version.
    UnsupportedVersion,
    /// An existing history database failed validation.
    Corrupt,
    /// The source generation advanced; this transaction was built from stale state.
    StaleGeneration,
    /// A competing observation of one candidate carries a different fingerprint.
    StageConflict,
    #[cfg(feature = "test-faults")]
    InjectedBeforeCommit,
    #[cfg(feature = "test-faults")]
    InjectedAfterCommit,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io => formatter.write_str("application store filesystem operation failed"),
            Self::Sqlite => formatter.write_str("application history transaction failed"),
            Self::CountOutOfRange => {
                formatter.write_str("reported token count exceeds storage range")
            }
            Self::InvalidRoot => formatter.write_str("canonical source root is not UTF-8"),
            Self::InvalidRelativePath => {
                formatter.write_str("source path is outside canonical root")
            }
            Self::InvalidStoredValue => {
                formatter.write_str("stored source-reported value is invalid")
            }
            Self::LimitExceeded => formatter.write_str("numeric acquisition limit exceeded"),
            Self::UnsafeFile => {
                formatter.write_str("history file is aliased or not a regular file")
            }
            Self::UnsupportedVersion => formatter.write_str("history database is newer"),
            Self::Corrupt => formatter.write_str("history database failed validation"),
            Self::StaleGeneration => formatter.write_str("source generation changed"),
            Self::StageConflict => formatter.write_str("competing observations differ"),
            #[cfg(feature = "test-faults")]
            Self::InjectedBeforeCommit => {
                formatter.write_str("test fault before transaction commit")
            }
            #[cfg(feature = "test-faults")]
            Self::InjectedAfterCommit => formatter.write_str("test fault after transaction commit"),
        }
    }
}

impl std::error::Error for StoreError {}

fn sqlite<T>(result: rusqlite::Result<T>) -> Result<T, StoreError> {
    result.map_err(|_| StoreError::Sqlite)
}

pub struct Store {
    connection: Connection,
    database: PathBuf,
    identity: (u64, u64),
    /// Device and inode of the data directory this store opened beneath its bound handle.
    data_identity: (u64, u64),
    #[cfg(feature = "test-faults")]
    fault: Option<FaultPoint>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitSummary {
    pub source_id: String,
    pub records_committed: u32,
    pub pending_groups: u32,
    /// Outcome after pending groups and sticky generation failures are applied.
    pub outcome: PassOutcome,
    pub failure: Option<FailureCode>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageSummary {
    pub records_committed: u32,
    pub pending_groups: u32,
}

/// Cursor of one database after a bounded read, bound to the identity it was read under.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgressUpdate {
    pub relative_path: PathBuf,
    pub next_cursor: Option<String>,
    pub identity: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SavedProgress {
    pub cursor: Option<String>,
    pub identity: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpoolFile {
    pub relative_path: PathBuf,
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub mtime_ns: i64,
    pub parser_kind: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileFailure {
    pub relative_path: PathBuf,
    pub code: FailureCode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingMark {
    pub relative_path: PathBuf,
    pub reason: FailureCode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KnownPath {
    pub relative_path: PathBuf,
    pub parser_kind: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryState {
    pub change_count: u32,
    pub next_retry_ms: Option<i64>,
    /// Why the source is backing off: `SourceChanging`, `SourceIdle` or `Busy`.
    pub reason: Option<FailureCode>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceRegistration {
    pub source_id: String,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiscardSummary {
    pub change_count: u32,
    pub next_retry_ms: i64,
    pub outcome: PassOutcome,
}

/// Work gathered by one acquisition pass.
#[derive(Clone, Copy, Default)]
pub struct StageBatch<'a> {
    /// Known source files revalidated this pass, so the next pass rotates to the others.
    pub visited: &'a [PathBuf],
    pub candidates: &'a [RecordCandidate],
    pub files: &'a [SpoolFile],
    pub progress: &'a [ProgressUpdate],
    pub failed: &'a [FileFailure],
    pub recovered: &'a [PathBuf],
    pub pending: &'a [PendingMark],
}

#[derive(Clone, Copy)]
pub struct StageRequest<'a> {
    pub source_id: &'a str,
    pub root: &'a Path,
    pub generation: u64,
    pub batch: StageBatch<'a>,
    /// The new durable frontier; `None` keeps the stored one untouched.
    pub frontier: Option<&'a [(PathBuf, usize, bool)]>,
    pub outcome: PassOutcome,
    pub failure: Option<FailureCode>,
    /// Record-level rejection that must outlive this pass within the generation.
    pub rejection: Option<FailureCode>,
    /// Schedule a durable idle/busy retry (`SourceIdle` or `Busy`) at this pass.
    pub backoff: Option<FailureCode>,
    /// A database read completed with an unchanged identity set (resets the change count).
    pub stable_read: bool,
    pub counters: PassCounters,
    pub now_ms: i64,
}

#[derive(Clone, Copy)]
pub struct CommitRequest<'a> {
    pub source_id: &'a str,
    pub root: &'a Path,
    pub generation: u64,
    pub batch: StageBatch<'a>,
    pub outcome: PassOutcome,
    pub failure: Option<FailureCode>,
    pub rejection: Option<FailureCode>,
    /// Every directory reached EOF with no unresolved error: unseen files may be classified missing.
    pub terminal: bool,
    pub counters: PassCounters,
    pub now_ms: i64,
}

#[derive(Clone, Copy)]
pub struct DiscardRequest<'a> {
    pub source_id: &'a str,
    pub generation: u64,
    pub failure: FailureCode,
    /// Source files (relative to the root) whose retained groups the change puts in doubt.
    pub paths: &'a [PathBuf],
    /// Groups (relative path, record id, format rank) a competing acquisition touched; they are
    /// restored to their pre-generation baseline.
    pub conflicts: &'a [(PathBuf, String, u8)],
    pub counters: PassCounters,
    pub now_ms: i64,
}

#[derive(Deserialize, Serialize)]
struct SpoolCandidate {
    relative_path: String,
    session_id: String,
    message_id: String,
    occurred_at_ms: i64,
    components: TokenComponents,
    #[serde(deserialize_with = "required_nullable")]
    total: Option<u64>,
    #[serde(deserialize_with = "required_nullable")]
    total_provenance: Option<Provenance>,
    #[serde(deserialize_with = "required_nullable")]
    source_convention: Option<String>,
    acquisition_consistency: AcquisitionConsistency,
    selected_part_ids: Vec<String>,
    pending_partial: bool,
    format_rank: u8,
    fingerprint: u64,
}

/// Regular, un-aliased history file: not a symlink, not hard-linked, not a special file.
fn regular_unaliased(metadata: &Metadata) -> bool {
    metadata.is_file() && metadata.nlink() == 1
}

/// Validates the history database and its sidecars; returns the database identity if it exists.
fn guard_files(database: &Path) -> Result<Option<(u64, u64)>, StoreError> {
    let mut identity = None;
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut name = database.as_os_str().to_owned();
        name.push(suffix);
        match std::fs::symlink_metadata(PathBuf::from(name)) {
            Ok(metadata) if regular_unaliased(&metadata) => {
                if suffix.is_empty() {
                    identity = Some((metadata.dev(), metadata.ino()));
                }
            }
            Ok(_) => return Err(StoreError::UnsafeFile),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(StoreError::Io),
        }
    }
    Ok(identity)
}

fn sidecar_path(database: &Path, suffix: &str) -> PathBuf {
    let mut name = database.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Refuses a newer, foreign or corrupt existing store before any writable open can change it.
///
/// Every check is effect free: nothing is opened for writing, created, recovered or deleted, so
/// a refused store keeps every database byte, sidecar and mode. The main-file header gives the
/// base version. A hot rollback journal is refused outright, because only a writable open could
/// recover it. A non-empty write-ahead log is walked frame by frame and its committed pages are
/// served over the main file through the read-only VFS, so the newest committed version and
/// schema are compared exactly as SQLite would see them after recovery.
fn prevalidate(database: &Path, file: &File) -> Result<(), StoreError> {
    let mut header = [0_u8; 100];
    let filled = {
        let mut filled = 0;
        while filled < header.len() {
            match file.read_at(&mut header[filled..], filled as u64) {
                Ok(0) => break,
                Ok(read) => filled += read,
                Err(_) => return Err(StoreError::Io),
            }
        }
        filled
    };
    if filled == 0 {
        return Ok(());
    }
    if filled < header.len() || !header.starts_with(b"SQLite format 3\0") {
        return Err(StoreError::Corrupt);
    }
    let version = i64::from(u32::from_be_bytes([
        header[60], header[61], header[62], header[63],
    ]));
    migrations::check_version(version).map_err(|_| StoreError::UnsupportedVersion)?;
    if sidecar_path(database, "-journal").exists() {
        return Err(StoreError::Corrupt);
    }
    let overlay = match crate::ingest::fs::open_regular(&sidecar_path(database, "-wal")) {
        Ok((wal, metadata)) if metadata.len() > 0 => {
            let overlay = sqlite_ro::WalOverlay::committed(wal).map_err(|_| StoreError::Corrupt)?;
            if let Some(committed) = overlay.user_version().map_err(|_| StoreError::Corrupt)? {
                migrations::check_version(i64::from(committed))
                    .map_err(|_| StoreError::UnsupportedVersion)?;
            }
            Some(overlay)
        }
        Ok(_) => None,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(StoreError::UnsafeFile),
    };
    with_rollback_view(database, overlay, |connection| {
        migrations::admit(connection).map(|_| ())
    })
    .map_err(|_| StoreError::Corrupt)?
}

fn backoff_ms(change_count: u32) -> i64 {
    let shift = change_count.saturating_sub(1).min(32);
    let delay = RETRY_INITIAL_MS
        .saturating_mul(1_u64 << shift)
        .min(RETRY_MAX_MS);
    i64::try_from(delay).unwrap_or(i64::MAX)
}

impl Store {
    /// Opens the history store under `data_dir`, binding to the nearest existing ancestor as it is
    /// right now. Callers that validated roots earlier use [`Store::open_bound`] instead.
    pub fn open(data_dir: &Path) -> Result<Self, StoreError> {
        let (data, anchor) = crate::discovery::anchor_for(data_dir).map_err(|_| StoreError::Io)?;
        Self::open_bound(&data, &anchor)
    }

    /// Opens the store beneath a directory handle bound to the validated `anchor`: every missing
    /// directory and the history file are created relative to that handle, never through a path
    /// that could have been redirected since validation. A replaced anchor is refused before
    /// anything is created or written.
    pub fn open_bound(data_dir: &Path, anchor: &DataAnchor) -> Result<Self, StoreError> {
        let relative = data_dir
            .strip_prefix(&anchor.path)
            .map_err(|_| StoreError::InvalidRoot)?;
        let mut directory =
            sqlite_ro::open_directory(&anchor.path).map_err(|_| StoreError::UnsafeFile)?;
        let held = directory.metadata().map_err(|_| StoreError::Io)?;
        if (held.dev(), held.ino()) != (anchor.device, anchor.inode) {
            return Err(StoreError::UnsafeFile);
        }
        for component in relative.components() {
            let std::path::Component::Normal(name) = component else {
                return Err(StoreError::InvalidRoot);
            };
            directory = sqlite_ro::open_or_create_directory_at(&directory, name)
                .map_err(|_| StoreError::UnsafeFile)?;
        }
        let data_identity = {
            let metadata = directory.metadata().map_err(|_| StoreError::Io)?;
            (metadata.dev(), metadata.ino())
        };
        let database = data_dir.join("history.sqlite");
        let (history, _created) =
            sqlite_ro::open_or_create_file_at(&directory, std::ffi::OsStr::new("history.sqlite"))
                .map_err(|error| match error.kind() {
                std::io::ErrorKind::NotFound => StoreError::Io,
                _ => StoreError::UnsafeFile,
            })?;
        let held = history.metadata().map_err(|_| StoreError::Io)?;
        if !regular_unaliased(&held) {
            return Err(StoreError::UnsafeFile);
        }
        let identity = (held.dev(), held.ino());
        // The path must name the very inode held through the bound handle, and so must every
        // sidecar be regular, before SQLite is asked to open anything by name.
        if guard_files(&database)? != Some(identity) {
            return Err(StoreError::UnsafeFile);
        }
        prevalidate(&database, &history)?;
        // The by-name open below is checked at the kernel level: the descriptor SQLite actually
        // obtains must be the inode held through the bound handle, and every sidecar it opens
        // must be regular and unaliased. A path swapped for the instant of the open (restored
        // before any later path check) is refused here, before any pragma or migration.
        let bind = sqlite_ro::bind_store(&database, identity).map_err(|_| StoreError::Sqlite)?;
        let mut connection = match Connection::open_with_flags(
            &database,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        ) {
            Ok(connection) => connection,
            Err(_) if bind.refused() => return Err(StoreError::UnsafeFile),
            Err(_) => return Err(StoreError::Sqlite),
        };
        if !bind.main_verified() || bind.refused() {
            return Err(StoreError::UnsafeFile);
        }
        // Opening wrote nothing yet; prove the path still names the held inode before the
        // first write.
        if guard_files(&database)? != Some(identity) {
            return Err(StoreError::UnsafeFile);
        }
        connection
            .busy_timeout(std::time::Duration::from_secs(1))
            .map_err(|_| StoreError::Sqlite)?;
        // A store with a non-empty log is admitted here, read only, before the mode pragma.
        migrations::admit(&connection)?;
        let journal_mode: String = connection
            .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
            .map_err(|_| {
                if bind.refused() {
                    StoreError::UnsafeFile
                } else {
                    StoreError::Sqlite
                }
            })?;
        if bind.refused() {
            return Err(StoreError::UnsafeFile);
        }
        if journal_mode != "wal" {
            return Err(StoreError::Sqlite);
        }
        guard_files(&database)?;
        migrations::migrate(&mut connection)?;
        Ok(Self {
            connection,
            database,
            identity,
            data_identity,
            #[cfg(feature = "test-faults")]
            fault: None,
        })
    }

    /// Device and inode of the data directory this store is bound to.
    pub fn data_identity(&self) -> (u64, u64) {
        self.data_identity
    }

    /// Re-proves, before a mutation, that the path still names the file this store opened.
    fn guard(&self) -> Result<(), StoreError> {
        if guard_files(&self.database)? == Some(self.identity) {
            Ok(())
        } else {
            Err(StoreError::UnsafeFile)
        }
    }

    fn begin(&mut self) -> Result<Transaction<'_>, StoreError> {
        self.guard()?;
        sqlite(
            self.connection
                .transaction_with_behavior(TransactionBehavior::Immediate),
        )
    }

    #[cfg(feature = "test-faults")]
    pub fn inject_fault(&mut self, point: FaultPoint) {
        self.fault = Some(point);
    }

    #[cfg(feature = "test-faults")]
    fn take_fault(&mut self) -> Option<FaultPoint> {
        self.fault.take()
    }

    pub fn register_source(
        &mut self,
        canonical_root: &Path,
        kind: SourceKind,
        root_identity: (u64, u64),
    ) -> Result<SourceRegistration, StoreError> {
        let root = canonical_root.to_str().ok_or(StoreError::InvalidRoot)?;
        let transaction = self.begin()?;
        let source_id = ensure_source(&transaction, root, kind.as_str())?;
        let (generation, device, inode): (i64, Option<i64>, Option<i64>) =
            sqlite(transaction.query_row(
                "SELECT generation, root_device, root_inode FROM sources WHERE source_id = ?1",
                [&source_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            ))?;
        let wanted = (sql_count(root_identity.0)?, sql_count(root_identity.1)?);
        if device.is_some() && (device, inode) != (Some(wanted.0), Some(wanted.1)) {
            // The source root was replaced: acquisition-local state describes another tree.
            clear_acquisition(&transaction, &source_id, generation)?;
        }
        sqlite(transaction.execute(
            "UPDATE sources SET root_device = ?2, root_inode = ?3 WHERE source_id = ?1",
            params![source_id, wanted.0, wanted.1],
        ))?;
        sqlite(transaction.commit())?;
        Ok(SourceRegistration {
            source_id,
            generation: u64::try_from(generation).map_err(|_| StoreError::InvalidStoredValue)?,
        })
    }

    pub fn generation(&self, source_id: &str) -> Result<u64, StoreError> {
        let generation: i64 = sqlite(self.connection.query_row(
            "SELECT generation FROM sources WHERE source_id = ?1",
            [source_id],
            |row| row.get(0),
        ))?;
        u64::try_from(generation).map_err(|_| StoreError::InvalidStoredValue)
    }

    pub fn retry_state(&self, source_id: &str) -> Result<RetryState, StoreError> {
        let (count, next, reason): (i64, Option<i64>, Option<String>) =
            sqlite(self.connection.query_row(
                "SELECT change_count, next_retry_ms, retry_reason FROM sources WHERE source_id = ?1",
                [source_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            ))?;
        let reason = match reason {
            None => None,
            Some(text) => Some(
                FailureCode::parse(&text)
                    .filter(|code| {
                        matches!(
                            code,
                            FailureCode::SourceChanging
                                | FailureCode::SourceIdle
                                | FailureCode::Busy
                        )
                    })
                    .ok_or(StoreError::InvalidStoredValue)?,
            ),
        };
        Ok(RetryState {
            change_count: u32::try_from(count).map_err(|_| StoreError::InvalidStoredValue)?,
            next_retry_ms: next,
            reason,
        })
    }

    pub fn saved_progress(
        &self,
        source_id: &str,
        relative_path: &Path,
        generation: u64,
    ) -> Result<Option<SavedProgress>, StoreError> {
        let path = relative_path
            .to_str()
            .ok_or(StoreError::InvalidRelativePath)?;
        let limit = i64::try_from(MAX_PROGRESS_CURSOR_BYTES).unwrap_or(i64::MAX);
        let progress: Option<(Option<String>, Option<i64>, Option<String>)> = sqlite(
            self.connection
                .query_row(
                    "SELECT CASE WHEN octet_length(working_cursor_key) <= ?4 THEN working_cursor_key END, \
                            octet_length(working_cursor_key), identity \
                     FROM opencode_progress \
                     WHERE source_id = ?1 AND acquisition_path = ?2 AND generation = ?3",
                    params![source_id, path, sql_count(generation)?, limit],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional(),
        )?;
        match progress {
            None => Ok(None),
            Some((None, Some(_), _)) => Err(StoreError::InvalidStoredValue),
            Some((cursor, _, identity)) => Ok(Some(SavedProgress { cursor, identity })),
        }
    }

    pub fn load_frontier(
        &self,
        source_id: &str,
        root: &Path,
        generation: u64,
    ) -> Result<Vec<(PathBuf, usize, bool)>, StoreError> {
        let mut statement = sqlite(self.connection.prepare(
            "SELECT relative_path, depth, restart_blocked FROM frontier_directories \
             WHERE source_id = ?1 AND generation = ?2 ORDER BY ordinal",
        ))?;
        let rows = sqlite(statement.query_map(
            params![source_id, sql_count(generation)?],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        ))?;
        let mut frontier = Vec::new();
        for row in rows {
            let (relative, depth, restart_blocked) = sqlite(row)?;
            let relative = checked_relative_path(&relative)?;
            let depth = usize::try_from(depth).map_err(|_| StoreError::InvalidStoredValue)?;
            let restart_blocked = match restart_blocked {
                0 => false,
                1 => true,
                _ => return Err(StoreError::InvalidStoredValue),
            };
            frontier.push((root.join(relative), depth, restart_blocked));
        }
        Ok(frontier)
    }

    pub fn generation_has_source_files(
        &self,
        source_id: &str,
        generation: u64,
    ) -> Result<bool, StoreError> {
        sqlite(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM metadata_spool \
             WHERE source_id = ?1 AND generation = ?2 AND parser_kind <> 'directory')",
            params![source_id, sql_count(generation)?],
            |row| row.get(0),
        ))
    }

    pub fn load_completed_directories(
        &self,
        source_id: &str,
        root: &Path,
        generation: u64,
    ) -> Result<Vec<PathBuf>, StoreError> {
        let mut statement = sqlite(self.connection.prepare(
            "SELECT relative_path FROM metadata_spool \
             WHERE source_id = ?1 AND generation = ?2 AND parser_kind = 'directory'",
        ))?;
        let rows = sqlite(
            statement.query_map(params![source_id, sql_count(generation)?], |row| {
                row.get::<_, String>(0)
            }),
        )?;
        rows.map(|row| Ok(root.join(checked_relative_path(&sqlite(row)?)?)))
            .collect()
    }

    /// Persisted source paths for the reserved current-file lane: databases first, then JSON
    /// messages, each least recently revalidated first (so every known path is reached in turn)
    /// and newest first among equals. Both queries seek the `source_files_known` index.
    pub fn known_paths(&self, source_id: &str, limit: usize) -> Result<Vec<KnownPath>, StoreError> {
        let mut known = Vec::new();
        for kind in ["sqlite", "opencode_json_message"] {
            let remaining = limit.saturating_sub(known.len());
            if remaining == 0 {
                break;
            }
            let mut statement = sqlite(self.connection.prepare(KNOWN_PATHS_SQL))?;
            let rows = sqlite(statement.query_map(
                params![
                    source_id,
                    kind,
                    i64::try_from(remaining).unwrap_or(i64::MAX)
                ],
                |row| row.get::<_, String>(0),
            ))?;
            for row in rows {
                known.push(KnownPath {
                    relative_path: checked_relative_path(&sqlite(row)?)?,
                    parser_kind: kind.to_owned(),
                });
            }
        }
        Ok(known)
    }

    /// Databases whose reading completed in this generation, with the identity set and main-file
    /// stamp they were read under, so a terminal pass can prove none of them changed since.
    pub fn completed_databases(
        &self,
        source_id: &str,
        generation: u64,
        after: Option<&Path>,
    ) -> Result<Vec<CompletedDatabase>, StoreError> {
        let after = match after {
            Some(path) => path.to_str().ok_or(StoreError::InvalidRelativePath)?,
            None => "",
        };
        let mut statement = sqlite(self.connection.prepare(
            "SELECT m.relative_path, m.device, m.inode, m.size, m.mtime_ns, p.identity \
             FROM metadata_spool m \
             JOIN opencode_progress p ON p.source_id = m.source_id \
               AND p.acquisition_path = m.relative_path AND p.generation = m.generation \
             WHERE m.source_id = ?1 AND m.generation = ?2 AND m.parser_kind = 'sqlite' \
               AND p.identity IS NOT NULL AND m.relative_path > ?4 \
             ORDER BY m.relative_path LIMIT ?3",
        ))?;
        let rows = sqlite(statement.query_map(
            params![
                source_id,
                sql_count(generation)?,
                i64::try_from(COMPLETED_DATABASE_PAGE).unwrap_or(i64::MAX),
                after
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        ))?;
        rows.map(|row| {
            let (relative, device, inode, size, mtime_ns, identity) = sqlite(row)?;
            Ok(CompletedDatabase {
                relative_path: checked_relative_path(&relative)?,
                device: u64::try_from(device).map_err(|_| StoreError::InvalidStoredValue)?,
                inode: u64::try_from(inode).map_err(|_| StoreError::InvalidStoredValue)?,
                size: u64::try_from(size).map_err(|_| StoreError::InvalidStoredValue)?,
                mtime_ns,
                identity,
            })
        })
        .collect()
    }

    pub fn load_failures(&self, source_id: &str) -> Result<Vec<FileFailure>, StoreError> {
        let mut statement = sqlite(self.connection.prepare(
            "SELECT relative_path, code FROM acquisition_failures \
             WHERE source_id = ?1 ORDER BY relative_path",
        ))?;
        let rows = sqlite(statement.query_map([source_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        }))?;
        rows.map(|row| {
            let (relative, code) = sqlite(row)?;
            Ok(FileFailure {
                relative_path: checked_relative_path(&relative)?,
                code: FailureCode::parse(&code).ok_or(StoreError::InvalidStoredValue)?,
            })
        })
        .collect()
    }

    pub fn load_staged_candidates(
        &self,
        source_id: &str,
        root: &Path,
        generation: u64,
    ) -> Result<Vec<RecordCandidate>, StoreError> {
        load_staged(&self.connection, source_id, root, generation)
    }
}

const KNOWN_PATHS_SQL: &str = "SELECT relative_path FROM source_files \
     WHERE source_id = ?1 AND adapter_state = ?2 AND file_state = 'present' \
     ORDER BY visit_seq, mtime_ns DESC, relative_path LIMIT ?3";

/// Known-path query text, exposed so tests can inspect its plan.
pub fn known_paths_sql() -> &'static str {
    KNOWN_PATHS_SQL
}

/// Completed databases returned per page of the terminal unchanged-proof; the proof walks every
/// page of the generation, so no database is left unchecked.
const COMPLETED_DATABASE_PAGE: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletedDatabase {
    pub relative_path: PathBuf,
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub mtime_ns: i64,
    /// Identity set (database and sidecars) the database was read under.
    pub identity: String,
}

impl Store {
    /// Stages one pass and publishes its completed groups in a single transaction. Staging alone
    /// never advances last-good; only a publication in this transaction does.
    pub fn stage_scan(&mut self, request: StageRequest<'_>) -> Result<StageSummary, StoreError> {
        #[cfg(feature = "test-faults")]
        let fault = self.take_fault();
        let transaction = self.begin()?;
        expect_generation(&transaction, request.source_id, request.generation)?;
        // An unfinished generation is reconciliation in progress: dirty until a clean terminal
        // completion clears it.
        sqlite(transaction.execute(
            "UPDATE sources SET dirty = 1 WHERE source_id = ?1",
            [request.source_id],
        ))?;
        let mut affected = BTreeSet::new();
        stage_batch(
            &transaction,
            request.source_id,
            request.root,
            request.generation,
            &request.batch,
            &mut affected,
        )?;
        if let Some(frontier) = request.frontier {
            sqlite(replace_frontier(
                &transaction,
                request.source_id,
                request.root,
                request.generation,
                frontier,
            ))?;
        }
        ensure_spool_capacity(&transaction, request.source_id, request.generation)?;
        let mut summary = StageSummary {
            records_committed: 0,
            pending_groups: 0,
        };
        for candidate in request.batch.candidates {
            match publish_candidate(
                &transaction,
                request.source_id,
                request.root,
                candidate,
                request.generation,
                &mut affected,
            )? {
                CandidateWrite::Saved => summary.records_committed += 1,
                CandidateWrite::Pending => summary.pending_groups += 1,
            }
        }
        recompute_all(&transaction, &affected, request.now_ms)?;
        // Publishing recorded baselines: every retained row counts before anything commits.
        ensure_spool_capacity(&transaction, request.source_id, request.generation)?;
        if let Some(code) = request.rejection {
            note_generation_failure(&transaction, request.source_id, code)?;
        }
        if request.stable_read {
            sqlite(transaction.execute(
                "UPDATE sources SET change_count = 0, next_retry_ms = NULL, retry_reason = NULL \
                 WHERE source_id = ?1",
                [request.source_id],
            ))?;
        }
        if let Some(reason) = request.backoff {
            schedule_retry(&transaction, request.source_id, reason, request.now_ms)?;
        }
        touch_visited(&transaction, request.source_id, request.batch.visited)?;
        let advance = summary.records_committed > 0 && request.outcome == PassOutcome::CatchingUp;
        save_status(
            &transaction,
            request.source_id,
            request.outcome,
            request.failure,
            request.counters,
            request.now_ms,
            advance,
        )?;
        #[cfg(feature = "test-faults")]
        if fault == Some(FaultPoint::BeforeCommit) {
            return Err(StoreError::InjectedBeforeCommit);
        }
        sqlite(transaction.commit())?;
        #[cfg(feature = "test-faults")]
        if fault == Some(FaultPoint::AfterCommit) {
            return Err(StoreError::InjectedAfterCommit);
        }
        Ok(summary)
    }

    /// Finalizes a generation: stages the last batch, publishes every staged group, applies the
    /// effective outcome, and advances the source generation, all or nothing.
    pub fn commit_generation(
        &mut self,
        request: CommitRequest<'_>,
    ) -> Result<CommitSummary, StoreError> {
        let next_generation = request
            .generation
            .checked_add(1)
            .ok_or(StoreError::CountOutOfRange)?;
        #[cfg(feature = "test-faults")]
        let fault = self.take_fault();
        let transaction = self.begin()?;
        expect_generation(&transaction, request.source_id, request.generation)?;
        let mut affected = BTreeSet::new();
        stage_batch(
            &transaction,
            request.source_id,
            request.root,
            request.generation,
            &request.batch,
            &mut affected,
        )?;
        ensure_spool_capacity(&transaction, request.source_id, request.generation)?;
        let staged = load_staged(
            &transaction,
            request.source_id,
            request.root,
            request.generation,
        )?;
        let mut records_committed = 0_u32;
        let mut pending_groups = 0_u32;
        for candidate in &staged {
            match publish_candidate(
                &transaction,
                request.source_id,
                request.root,
                candidate,
                request.generation,
                &mut affected,
            )? {
                CandidateWrite::Saved => records_committed = records_committed.saturating_add(1),
                CandidateWrite::Pending => pending_groups = pending_groups.saturating_add(1),
            }
        }
        recompute_all(&transaction, &affected, request.now_ms)?;
        if let Some(code) = request.rejection {
            note_generation_failure(&transaction, request.source_id, code)?;
        }
        sqlite(transaction.execute(
            "INSERT INTO source_files(\
                source_id, relative_path, device, inode, size, mtime_ns, byte_offset, \
                first_line_fnv64, adapter_state, parse_generation, file_state\
             ) SELECT source_id, relative_path, device, inode, size, mtime_ns, 0, 0, \
                parser_kind, generation, 'present' FROM metadata_spool \
             WHERE source_id = ?1 AND generation = ?2 AND parser_kind <> 'directory' \
             ON CONFLICT(source_id, relative_path) DO UPDATE SET \
                device = excluded.device, inode = excluded.inode, size = excluded.size, \
                mtime_ns = excluded.mtime_ns, parse_generation = excluded.parse_generation, \
                file_state = 'present', adapter_state = excluded.adapter_state",
            params![request.source_id, sql_count(request.generation)?],
        ))?;
        let sticky: Option<String> = sqlite(transaction.query_row(
            "SELECT generation_failure FROM sources WHERE source_id = ?1",
            [request.source_id],
            |row| row.get(0),
        ))?;
        let sticky = sticky.as_deref().and_then(FailureCode::parse);
        if request.terminal && sticky.is_none() {
            // Only a sweep that reached every directory cleanly may call an unseen file missing.
            sqlite(transaction.execute(
                "UPDATE source_files SET file_state = 'missing' \
                 WHERE source_id = ?1 AND file_state = 'present' AND relative_path NOT IN (\
                     SELECT relative_path FROM metadata_spool WHERE source_id = ?1 AND generation = ?2)",
                params![request.source_id, sql_count(request.generation)?],
            ))?;
        }
        let mut outcome = request.outcome;
        let mut failure = request.failure.or(sticky);
        if outcome == PassOutcome::Consistent && (pending_groups > 0 || sticky.is_some()) {
            outcome = PassOutcome::Partial;
            failure = failure.or(Some(FailureCode::InvalidRecord));
        }
        clear_acquisition(
            &transaction,
            request.source_id,
            sql_count(request.generation)?,
        )?;
        let clean = outcome == PassOutcome::Consistent;
        sqlite(transaction.execute(
            "UPDATE sources SET generation = ?2, generation_failure = NULL, \
                dirty = CASE WHEN ?3 THEN 0 ELSE 1 END, \
                change_count = CASE WHEN ?3 THEN 0 ELSE change_count END, \
                next_retry_ms = CASE WHEN ?3 THEN NULL ELSE next_retry_ms END, \
                retry_reason = CASE WHEN ?3 THEN NULL ELSE retry_reason END \
             WHERE source_id = ?1",
            params![request.source_id, sql_count(next_generation)?, clean],
        ))?;
        touch_visited(&transaction, request.source_id, request.batch.visited)?;
        save_status(
            &transaction,
            request.source_id,
            outcome,
            failure,
            request.counters,
            request.now_ms,
            clean,
        )?;
        #[cfg(feature = "test-faults")]
        if fault == Some(FaultPoint::BeforeCommit) {
            return Err(StoreError::InjectedBeforeCommit);
        }
        sqlite(transaction.commit())?;
        #[cfg(feature = "test-faults")]
        if fault == Some(FaultPoint::AfterCommit) {
            return Err(StoreError::InjectedAfterCommit);
        }
        Ok(CommitSummary {
            source_id: request.source_id.to_owned(),
            records_committed,
            pending_groups,
            outcome,
            failure,
        })
    }

    /// Drops the acquisition-local state of a generation whose source changed, restores every
    /// group a competing acquisition touched to its pre-generation baseline, keeps the rest of
    /// the committed history (flagging affected groups pending), and schedules the retry.
    pub fn discard_generation(
        &mut self,
        request: DiscardRequest<'_>,
    ) -> Result<DiscardSummary, StoreError> {
        #[cfg(feature = "test-faults")]
        let fault = self.take_fault();
        let transaction = self.begin()?;
        expect_generation(&transaction, request.source_id, request.generation)?;
        let mut keys = staged_event_keys(&transaction, request.source_id, request.generation)?;
        for (path, event_key, rank) in request.conflicts {
            let relative = relative_text(Path::new("."), path)?;
            restore_baseline(
                &transaction,
                request.source_id,
                request.generation,
                event_key,
                i64::from(*rank),
                &relative,
            )?;
            keys.push(event_key.clone());
        }
        for path in request.paths {
            let relative = relative_text(Path::new("."), path)?;
            let mut statement = sqlite(transaction.prepare(
                "SELECT DISTINCT event_key FROM reported_groups \
                 WHERE source_id = ?1 AND mirror_path = ?2",
            ))?;
            let rows = sqlite(
                statement.query_map(params![request.source_id, relative], |row| {
                    row.get::<_, String>(0)
                }),
            )?;
            for key in rows {
                keys.push(sqlite(key)?);
            }
        }
        keys.sort();
        keys.dedup();
        for key in keys {
            sqlite(transaction.execute(
                "UPDATE reported_groups SET pending_partial = 1, pending_reason = ?3 \
                 WHERE source_id = ?1 AND event_key = ?2",
                params![request.source_id, key, request.failure.as_str()],
            ))?;
            recompute_event(&transaction, &key, request.now_ms)?;
        }
        clear_acquisition(
            &transaction,
            request.source_id,
            sql_count(request.generation)?,
        )?;
        sqlite(transaction.execute(
            "UPDATE sources SET dirty = 1 WHERE source_id = ?1",
            [request.source_id],
        ))?;
        let (change_count, next_retry_ms) = schedule_retry(
            &transaction,
            request.source_id,
            request.failure,
            request.now_ms,
        )?;
        let outcome = retry_outcome(request.failure, change_count);
        save_status(
            &transaction,
            request.source_id,
            outcome,
            Some(request.failure),
            request.counters,
            request.now_ms,
            false,
        )?;
        #[cfg(feature = "test-faults")]
        if fault == Some(FaultPoint::BeforeCommit) {
            return Err(StoreError::InjectedBeforeCommit);
        }
        sqlite(transaction.commit())?;
        #[cfg(feature = "test-faults")]
        if fault == Some(FaultPoint::AfterCommit) {
            return Err(StoreError::InjectedAfterCommit);
        }
        Ok(DiscardSummary {
            change_count,
            next_retry_ms,
            outcome,
        })
    }

    /// Rebuilds acquisition-local state: removes staged candidates, metadata, frontier and
    /// working cursors of a generation while keeping everything published.
    pub fn reset_acquisition(
        &mut self,
        source_id: &str,
        generation: u64,
    ) -> Result<(), StoreError> {
        let transaction = self.begin()?;
        expect_generation(&transaction, source_id, generation)?;
        clear_acquisition(&transaction, source_id, sql_count(generation)?)?;
        sqlite(transaction.commit())
    }
}

/// Outcome of a source that is backing off: only a source that keeps changing escalates (third
/// consecutive); idle and busy sources are already unavailable.
pub fn retry_outcome(reason: FailureCode, change_count: u32) -> PassOutcome {
    if reason == FailureCode::SourceChanging && change_count < u32::from(SOURCE_CHANGING_RETRIES) {
        PassOutcome::Partial
    } else {
        PassOutcome::Unavailable
    }
}

/// Counts one more consecutive failure of the same kind (a different kind restarts the count)
/// and schedules the next permitted attempt: 5 s doubling to 5 min.
fn schedule_retry(
    transaction: &Transaction<'_>,
    source_id: &str,
    reason: FailureCode,
    now_ms: i64,
) -> Result<(u32, i64), StoreError> {
    let count: i64 = sqlite(transaction.query_row(
        "UPDATE sources SET \
            change_count = CASE WHEN retry_reason IS ?2 THEN change_count + 1 ELSE 1 END, \
            retry_reason = ?2 \
         WHERE source_id = ?1 RETURNING change_count",
        params![source_id, reason.as_str()],
        |row| row.get(0),
    ))?;
    let change_count = u32::try_from(count).map_err(|_| StoreError::InvalidStoredValue)?;
    let next_retry_ms = now_ms.saturating_add(backoff_ms(change_count));
    sqlite(transaction.execute(
        "UPDATE sources SET next_retry_ms = ?2 WHERE source_id = ?1",
        params![source_id, next_retry_ms],
    ))?;
    Ok((change_count, next_retry_ms))
}

/// Marks revalidated known files, so the bounded current lane rotates through all of them.
fn touch_visited(
    transaction: &Transaction<'_>,
    source_id: &str,
    visited: &[PathBuf],
) -> Result<(), StoreError> {
    if visited.is_empty() {
        return Ok(());
    }
    let clock: i64 = sqlite(transaction.query_row(
        "UPDATE sources SET known_clock = known_clock + 1 WHERE source_id = ?1 \
         RETURNING known_clock",
        [source_id],
        |row| row.get(0),
    ))?;
    for path in visited {
        let relative = relative_text(Path::new("."), path)?;
        sqlite(transaction.execute(
            "UPDATE source_files SET visit_seq = ?3 WHERE source_id = ?1 AND relative_path = ?2",
            params![source_id, relative, clock],
        ))?;
    }
    Ok(())
}

fn expect_generation(
    transaction: &Transaction<'_>,
    source_id: &str,
    expected: u64,
) -> Result<(), StoreError> {
    let current: i64 = sqlite(transaction.query_row(
        "SELECT generation FROM sources WHERE source_id = ?1",
        [source_id],
        |row| row.get(0),
    ))?;
    if current == sql_count(expected)? {
        Ok(())
    } else {
        Err(StoreError::StaleGeneration)
    }
}

fn clear_acquisition(
    transaction: &Transaction<'_>,
    source_id: &str,
    generation: i64,
) -> Result<(), StoreError> {
    for table in [
        "opencode_candidate_spool",
        "metadata_spool",
        "frontier_directories",
        "group_baseline",
    ] {
        sqlite(transaction.execute(
            &format!("DELETE FROM {table} WHERE source_id = ?1 AND generation = ?2"),
            params![source_id, generation],
        ))?;
    }
    sqlite(transaction.execute(
        "DELETE FROM opencode_progress WHERE source_id = ?1",
        [source_id],
    ))?;
    Ok(())
}

fn note_generation_failure(
    transaction: &Transaction<'_>,
    source_id: &str,
    code: FailureCode,
) -> Result<(), StoreError> {
    sqlite(transaction.execute(
        "UPDATE sources SET generation_failure = COALESCE(generation_failure, ?2) \
         WHERE source_id = ?1",
        params![source_id, code.as_str()],
    ))?;
    Ok(())
}

fn staged_event_keys(
    transaction: &Transaction<'_>,
    source_id: &str,
    generation: u64,
) -> Result<Vec<String>, StoreError> {
    let mut statement = sqlite(transaction.prepare(
        "SELECT DISTINCT event_key FROM opencode_candidate_spool \
         WHERE source_id = ?1 AND generation = ?2",
    ))?;
    let rows = sqlite(
        statement.query_map(params![source_id, sql_count(generation)?], |row| {
            row.get::<_, String>(0)
        }),
    )?;
    rows.map(sqlite).collect()
}

fn load_staged(
    connection: &Connection,
    source_id: &str,
    root: &Path,
    generation: u64,
) -> Result<Vec<RecordCandidate>, StoreError> {
    let mut statement = sqlite(connection.prepare(
        "SELECT relative_path, candidate_json, event_key, format_rank, fingerprint \
         FROM opencode_candidate_spool WHERE source_id = ?1 AND generation = ?2 \
         ORDER BY relative_path, event_key, format_rank, fingerprint",
    ))?;
    let rows = sqlite(
        statement.query_map(params![source_id, sql_count(generation)?], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
            ))
        }),
    )?;
    let mut candidates = Vec::new();
    for row in rows {
        let (relative, json, event_key, rank, fingerprint) = sqlite(row)?;
        let stored: SpoolCandidate =
            serde_json::from_str(&json).map_err(|_| StoreError::InvalidStoredValue)?;
        if stored.relative_path != relative
            || i64::from(stored.format_rank) != rank
            || format!("{:016x}", stored.fingerprint) != fingerprint
        {
            return Err(StoreError::InvalidStoredValue);
        }
        let record = stored.into_record(root)?;
        if record.record_id() != event_key {
            return Err(StoreError::InvalidStoredValue);
        }
        candidates.push(record);
    }
    Ok(candidates)
}

fn replace_frontier(
    transaction: &Transaction<'_>,
    source_id: &str,
    root: &Path,
    generation: u64,
    frontier: &[(PathBuf, usize, bool)],
) -> rusqlite::Result<()> {
    let generation = i64::try_from(generation).map_err(|_| rusqlite::Error::InvalidQuery)?;
    transaction.execute(
        "DELETE FROM frontier_directories WHERE source_id = ?1 AND generation = ?2",
        params![source_id, generation],
    )?;
    for (ordinal, (path, depth, restart_blocked)) in frontier.iter().enumerate() {
        let relative = relative_text(root, path).map_err(|_| rusqlite::Error::InvalidQuery)?;
        transaction.execute(
            "INSERT INTO frontier_directories(source_id, generation, relative_path, depth, ordinal, restart_blocked) \
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                source_id,
                generation,
                relative,
                i64::try_from(*depth).map_err(|_| rusqlite::Error::InvalidQuery)?,
                i64::try_from(ordinal).map_err(|_| rusqlite::Error::InvalidQuery)?,
                i64::from(*restart_blocked),
            ],
        )?;
    }
    Ok(())
}

/// Writes a batch into the generation's spool. Tie and stale-state failures abort the whole
/// transaction, so the durable frontier and cursors are never partly advanced.
fn stage_batch(
    transaction: &Transaction<'_>,
    source_id: &str,
    root: &Path,
    generation: u64,
    batch: &StageBatch<'_>,
    affected: &mut BTreeSet<String>,
) -> Result<(), StoreError> {
    let generation_sql = sql_count(generation)?;
    for candidate in batch.candidates {
        validate_candidate(candidate)?;
        let relative = relative_text(root, &candidate.canonical_path)?;
        let stored = SpoolCandidate::from_record(candidate, relative.clone());
        let json = serde_json::to_string(&stored).map_err(|_| StoreError::Sqlite)?;
        let fingerprint = format!("{:016x}", candidate.fingerprint);
        let event_key = candidate.record_id();
        let rank = i64::from(candidate.format_rank);
        let rivals: Vec<String> = {
            let mut statement = sqlite(transaction.prepare(
                "SELECT fingerprint FROM opencode_candidate_spool \
                 WHERE source_id = ?1 AND generation = ?2 AND relative_path = ?3 \
                   AND event_key = ?4 AND format_rank = ?5",
            ))?;
            let rows = sqlite(statement.query_map(
                params![source_id, generation_sql, relative, event_key, rank],
                |row| row.get::<_, String>(0),
            ))?;
            rows.map(sqlite).collect::<Result<_, _>>()?
        };
        if rivals.contains(&fingerprint) {
            continue;
        }
        if !rivals.is_empty() {
            return Err(StoreError::StageConflict);
        }
        sqlite(transaction.execute(
            "INSERT INTO opencode_candidate_spool(source_id, generation, relative_path, event_key, format_rank, fingerprint, candidate_json) \
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![source_id, generation_sql, relative, event_key, rank, fingerprint, json],
        ))?;
    }
    for file in batch.files {
        let relative = relative_text(Path::new("."), &file.relative_path)?;
        sqlite(transaction.execute(
            "INSERT INTO metadata_spool(source_id, generation, relative_path, device, inode, size, mtime_ns, parser_kind) \
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
             ON CONFLICT(source_id, generation, relative_path) DO UPDATE SET \
                device = excluded.device, inode = excluded.inode, size = excluded.size, \
                mtime_ns = excluded.mtime_ns, parser_kind = excluded.parser_kind",
            params![
                source_id,
                generation_sql,
                relative,
                sql_count(file.device)?,
                sql_count(file.inode)?,
                sql_count(file.size)?,
                file.mtime_ns,
                file.parser_kind
            ],
        ))?;
    }
    for update in batch.progress {
        let relative = relative_text(Path::new("."), &update.relative_path)?;
        if update
            .next_cursor
            .as_ref()
            .is_some_and(|cursor| cursor.len() > MAX_PROGRESS_CURSOR_BYTES)
        {
            return Err(StoreError::LimitExceeded);
        }
        sqlite(transaction.execute(
            "INSERT INTO opencode_progress(source_id, acquisition_path, generation, working_cursor_key, identity) \
             VALUES(?1, ?2, ?3, ?4, ?5) \
             ON CONFLICT(source_id, acquisition_path) DO UPDATE SET \
                generation = excluded.generation, working_cursor_key = excluded.working_cursor_key, \
                identity = excluded.identity",
            params![source_id, relative, generation_sql, update.next_cursor, update.identity],
        ))?;
    }
    for failure in batch.failed {
        let relative = relative_text(Path::new("."), &failure.relative_path)?;
        let known: bool = sqlite(transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM acquisition_failures WHERE source_id = ?1 AND relative_path = ?2)",
            params![source_id, relative],
            |row| row.get(0),
        ))?;
        if !known {
            let total: i64 = sqlite(transaction.query_row(
                "SELECT COUNT(*) FROM acquisition_failures WHERE source_id = ?1",
                [source_id],
                |row| row.get(0),
            ))?;
            if usize::try_from(total).map_err(|_| StoreError::LimitExceeded)? >= MAX_FAILED_FILES {
                return Err(StoreError::LimitExceeded);
            }
        }
        sqlite(transaction.execute(
            "INSERT INTO acquisition_failures(source_id, relative_path, code, attempts) \
             VALUES(?1, ?2, ?3, 1) \
             ON CONFLICT(source_id, relative_path) DO UPDATE SET \
                code = excluded.code, attempts = attempts + 1",
            params![source_id, relative, failure.code.as_str()],
        ))?;
    }
    for recovered in batch.recovered {
        let relative = relative_text(Path::new("."), recovered)?;
        sqlite(transaction.execute(
            "DELETE FROM acquisition_failures WHERE source_id = ?1 AND relative_path = ?2",
            params![source_id, relative],
        ))?;
    }
    for mark in batch.pending {
        let relative = relative_text(Path::new("."), &mark.relative_path)?;
        let keys: Vec<String> = {
            let mut statement = sqlite(transaction.prepare(
                "SELECT DISTINCT event_key FROM reported_groups \
                 WHERE source_id = ?1 AND mirror_path = ?2",
            ))?;
            let rows = sqlite(
                statement.query_map(params![source_id, relative], |row| row.get::<_, String>(0)),
            )?;
            rows.map(sqlite).collect::<Result<_, _>>()?
        };
        sqlite(transaction.execute(
            "UPDATE reported_groups SET pending_partial = 1, pending_reason = ?3 \
             WHERE source_id = ?1 AND mirror_path = ?2",
            params![source_id, relative, mark.reason.as_str()],
        ))?;
        for key in keys {
            affected.insert(key);
        }
    }
    Ok(())
}

/// Rows and UTF-8 octets of every column the generation retains while it is acquired: staged
/// candidates, file metadata, the durable frontier, the per-database working cursors and
/// identities, and the group baselines kept for rollback. Octets, never characters.
fn ensure_spool_capacity(
    transaction: &Transaction<'_>,
    source_id: &str,
    generation: u64,
) -> Result<(), StoreError> {
    let (rows, bytes): (i64, i64) = sqlite(transaction.query_row(
        "SELECT \
            (SELECT COUNT(*) FROM opencode_candidate_spool WHERE source_id = ?1 AND generation = ?2) + \
            (SELECT COUNT(*) FROM metadata_spool WHERE source_id = ?1 AND generation = ?2) + \
            (SELECT COUNT(*) FROM frontier_directories WHERE source_id = ?1 AND generation = ?2) + \
            (SELECT COUNT(*) FROM opencode_progress WHERE source_id = ?1 AND generation = ?2) + \
            (SELECT COUNT(*) FROM group_baseline WHERE source_id = ?1 AND generation = ?2), \
            (SELECT COALESCE(SUM(octet_length(relative_path) + octet_length(event_key) + \
                octet_length(fingerprint) + octet_length(candidate_json)), 0) \
               FROM opencode_candidate_spool WHERE source_id = ?1 AND generation = ?2) + \
            (SELECT COALESCE(SUM(octet_length(relative_path) + octet_length(parser_kind)), 0) \
               FROM metadata_spool WHERE source_id = ?1 AND generation = ?2) + \
            (SELECT COALESCE(SUM(octet_length(relative_path)), 0) \
               FROM frontier_directories WHERE source_id = ?1 AND generation = ?2) + \
            (SELECT COALESCE(SUM(octet_length(acquisition_path) + \
                octet_length(COALESCE(working_cursor_key, '')) + \
                octet_length(COALESCE(identity, ''))), 0) \
               FROM opencode_progress WHERE source_id = ?1 AND generation = ?2) + \
            (SELECT COALESCE(SUM(octet_length(event_key) + octet_length(mirror_path) + \
                octet_length(COALESCE(prior_json, ''))), 0) \
               FROM group_baseline WHERE source_id = ?1 AND generation = ?2)",
        params![source_id, sql_count(generation)?],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ))?;
    if rows < 0
        || bytes < 0
        || usize::try_from(rows).map_err(|_| StoreError::LimitExceeded)? > MAX_METADATA_SPOOL_ROWS
        || usize::try_from(bytes).map_err(|_| StoreError::LimitExceeded)? > MAX_METADATA_SPOOL_BYTES
    {
        return Err(StoreError::LimitExceeded);
    }
    Ok(())
}

/// Store-side record guard, independent of the adapter: nothing above the normative numeric
/// ceiling, outside the calendar range or with a malformed identity may be staged, published or
/// read back from the spool, whatever the total claims, and total metadata must be coherent.
fn validate_candidate(candidate: &RecordCandidate) -> Result<(), StoreError> {
    let components = &candidate.components;
    let oversized = [
        components.input,
        components.output,
        components.reasoning,
        components.cache_read,
        components.cache_write,
        candidate.total,
    ]
    .into_iter()
    .flatten()
    .any(|value| value > MAX_TOKEN_COUNT);
    if oversized {
        return Err(StoreError::CountOutOfRange);
    }
    if !total_metadata_is_valid(
        candidate.total,
        candidate.total_provenance,
        candidate.source_convention.as_deref(),
    ) {
        return Err(StoreError::InvalidStoredValue);
    }
    let parts = &candidate.selected_part_ids;
    if !(0..=MAX_SOURCE_TIMESTAMP_MS).contains(&candidate.occurred_at_ms)
        || !is_valid_id_component(&candidate.session_id)
        || !is_valid_id_component(&candidate.message_id)
        || candidate.session_id.len() + candidate.message_id.len() > MAX_RECORD_ID_BYTES
        || parts.len() > MAX_SELECTED_PART_IDS
        || parts.iter().any(|part| !is_valid_id_component(part))
        || parts.iter().collect::<BTreeSet<_>>().len() != parts.len()
    {
        return Err(StoreError::InvalidStoredValue);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CandidateWrite {
    Saved,
    Pending,
}

fn ensure_source(
    transaction: &Transaction<'_>,
    canonical_root: &str,
    kind: &str,
) -> Result<String, StoreError> {
    let existing = sqlite(
        transaction
            .query_row(
                "SELECT source_id FROM sources WHERE canonical_root = ?1",
                [canonical_root],
                |row| row.get(0),
            )
            .optional(),
    )?;
    if let Some(source_id) = existing {
        sqlite(transaction.execute(
            "UPDATE sources SET consent = ?2 WHERE source_id = ?1",
            params![source_id, ConsentState::Enabled.as_str()],
        ))?;
        return Ok(source_id);
    }
    sqlite(transaction.query_row(
        "INSERT INTO sources(source_id, harness, canonical_root, kind, consent) \
         VALUES(lower(hex(randomblob(16))), 'opencode', ?1, ?2, 'enabled') RETURNING source_id",
        params![canonical_root, kind],
        |row| row.get(0),
    ))
}

fn unsigned(value: Option<i64>) -> Result<Option<u64>, StoreError> {
    value
        .map(|value| u64::try_from(value).map_err(|_| StoreError::InvalidStoredValue))
        .transpose()
}

/// One persisted mirror group: the numbers and metadata one source file reported for a record.
#[derive(Deserialize, Serialize)]
struct StoredGroup {
    session_id: String,
    message_id: String,
    occurred_at_ms: i64,
    values: [Option<i64>; 6],
    total_provenance: Option<String>,
    source_convention: Option<String>,
    acquisition_consistency: String,
    part_ids: String,
    pending_partial: bool,
    pending_reason: Option<String>,
    generation: i64,
}

const GROUP_COLUMNS: &str = "session_id, message_id, occurred_at_ms, input_tokens, output_tokens, \
     reasoning_tokens, cache_read_tokens, cache_write_tokens, total_tokens, total_provenance, \
     source_convention, acquisition_consistency, part_ids, pending_partial, pending_reason, \
     generation";

fn read_group(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredGroup> {
    Ok(StoredGroup {
        session_id: row.get(0)?,
        message_id: row.get(1)?,
        occurred_at_ms: row.get(2)?,
        values: [
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
            row.get(7)?,
            row.get(8)?,
        ],
        total_provenance: row.get(9)?,
        source_convention: row.get(10)?,
        acquisition_consistency: row.get(11)?,
        part_ids: row.get(12)?,
        pending_partial: row.get::<_, i64>(13)? != 0,
        pending_reason: row.get(14)?,
        generation: row.get(15)?,
    })
}

/// Remembers a group's pre-generation state the first time a generation rewrites it, so a
/// conflicting acquisition can be rolled back to the last good value. At most one row per
/// published group, so it is bounded by the staged candidates.
fn record_baseline(
    transaction: &Transaction<'_>,
    source_id: &str,
    generation: i64,
    event_key: &str,
    rank: i64,
    path: &str,
) -> Result<(), StoreError> {
    let exists: bool = sqlite(transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM group_baseline WHERE source_id = ?1 AND generation = ?2 \
           AND event_key = ?3 AND format_rank = ?4 AND mirror_path = ?5)",
        params![source_id, generation, event_key, rank, path],
        |row| row.get(0),
    ))?;
    if exists {
        return Ok(());
    }
    let prior = sqlite(
        transaction
            .query_row(
                &format!(
                    "SELECT {GROUP_COLUMNS} FROM reported_groups WHERE source_id = ?1 \
                     AND event_key = ?2 AND format_rank = ?3 AND mirror_path = ?4"
                ),
                params![source_id, event_key, rank, path],
                read_group,
            )
            .optional(),
    )?;
    let prior_json = prior
        .map(|group| serde_json::to_string(&group).map_err(|_| StoreError::Sqlite))
        .transpose()?;
    sqlite(transaction.execute(
        "INSERT INTO group_baseline(source_id, generation, event_key, format_rank, mirror_path, prior_json) \
         VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
        params![source_id, generation, event_key, rank, path, prior_json],
    ))?;
    Ok(())
}

/// Puts a group back to the state it had before this generation touched it.
fn restore_baseline(
    transaction: &Transaction<'_>,
    source_id: &str,
    generation: u64,
    event_key: &str,
    rank: i64,
    path: &str,
) -> Result<(), StoreError> {
    let generation = sql_count(generation)?;
    let baseline: Option<Option<String>> = sqlite(
        transaction
            .query_row(
                "SELECT prior_json FROM group_baseline WHERE source_id = ?1 AND generation = ?2 \
                 AND event_key = ?3 AND format_rank = ?4 AND mirror_path = ?5",
                params![source_id, generation, event_key, rank, path],
                |row| row.get(0),
            )
            .optional(),
    )?;
    let Some(prior) = baseline else {
        return Ok(());
    };
    match prior {
        None => {
            sqlite(transaction.execute(
                "DELETE FROM reported_groups WHERE source_id = ?1 AND event_key = ?2 \
                 AND format_rank = ?3 AND mirror_path = ?4",
                params![source_id, event_key, rank, path],
            ))?;
        }
        Some(json) => {
            let group: StoredGroup =
                serde_json::from_str(&json).map_err(|_| StoreError::InvalidStoredValue)?;
            write_group(transaction, source_id, event_key, rank, path, &group)?;
        }
    }
    Ok(())
}

fn write_group(
    transaction: &Transaction<'_>,
    source_id: &str,
    event_key: &str,
    rank: i64,
    path: &str,
    group: &StoredGroup,
) -> Result<(), StoreError> {
    sqlite(transaction.execute(
        "INSERT INTO reported_groups(source_id, event_key, format_rank, mirror_path, session_id, \
            message_id, occurred_at_ms, input_tokens, output_tokens, reasoning_tokens, \
            cache_read_tokens, cache_write_tokens, total_tokens, total_provenance, \
            source_convention, acquisition_consistency, part_ids, pending_partial, pending_reason, \
            generation) \
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, \
            ?19, ?20) \
         ON CONFLICT(source_id, event_key, format_rank, mirror_path) DO UPDATE SET \
            session_id = excluded.session_id, message_id = excluded.message_id, \
            occurred_at_ms = excluded.occurred_at_ms, input_tokens = excluded.input_tokens, \
            output_tokens = excluded.output_tokens, reasoning_tokens = excluded.reasoning_tokens, \
            cache_read_tokens = excluded.cache_read_tokens, \
            cache_write_tokens = excluded.cache_write_tokens, \
            total_tokens = excluded.total_tokens, total_provenance = excluded.total_provenance, \
            source_convention = excluded.source_convention, \
            acquisition_consistency = excluded.acquisition_consistency, \
            part_ids = excluded.part_ids, pending_partial = excluded.pending_partial, \
            pending_reason = excluded.pending_reason, generation = excluded.generation",
        params![
            source_id,
            event_key,
            rank,
            path,
            group.session_id,
            group.message_id,
            group.occurred_at_ms,
            group.values[0],
            group.values[1],
            group.values[2],
            group.values[3],
            group.values[4],
            group.values[5],
            group.total_provenance,
            group.source_convention,
            group.acquisition_consistency,
            group.part_ids,
            i64::from(group.pending_partial),
            group.pending_reason,
            group.generation,
        ],
    ))?;
    Ok(())
}

/// What the numeric projection needs of one published record.
#[derive(Clone, Debug, Eq, PartialEq)]
struct EventSummary {
    source_id: String,
    values: [Option<i64>; 6],
    derived_total: bool,
    mismatch: bool,
    conflict: bool,
    pending: bool,
    consistency: AcquisitionConsistency,
}

/// Counters of one source: records, then (count, sum) of the six numeric fields, then the
/// derived-total, mismatch, conflict, pending, SQLite-labelled and JSON-labelled record counts.
const PROJECTION_COLUMNS: [&str; 19] = [
    "records",
    "input_count",
    "input_sum",
    "output_count",
    "output_sum",
    "reasoning_count",
    "reasoning_sum",
    "cache_read_count",
    "cache_read_sum",
    "cache_write_count",
    "cache_write_sum",
    "total_count",
    "total_sum",
    "derived_total_count",
    "mismatch_count",
    "conflict_count",
    "pending_count",
    "sqlite_count",
    "json_count",
];

fn projection_totals(
    connection: &Connection,
    source_id: &str,
) -> Result<Option<[i64; 19]>, StoreError> {
    let select = PROJECTION_COLUMNS.join(", ");
    sqlite(
        connection
            .query_row(
                &format!("SELECT {select} FROM source_projection_totals WHERE source_id = ?1"),
                [source_id],
                |row| {
                    let mut totals = [0_i64; 19];
                    for (index, slot) in totals.iter_mut().enumerate() {
                        *slot = row.get(index)?;
                    }
                    Ok(totals)
                },
            )
            .optional(),
    )
}

/// Adds (`sign` 1) or removes (`sign` -1) one record from its source's maintained projection,
/// in the same transaction that changes the record. Sums are checked; an unrepresentable sum is
/// an error, never a wrapped or clamped number.
fn apply_summary(
    transaction: &Transaction<'_>,
    summary: &EventSummary,
    sign: i64,
) -> Result<(), StoreError> {
    sqlite(transaction.execute(
        "INSERT OR IGNORE INTO source_projection_totals VALUES (?1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)",
        [&summary.source_id],
    ))?;
    let mut totals = projection_totals(transaction, &summary.source_id)?
        .ok_or(StoreError::InvalidStoredValue)?;
    let mut add = |index: usize, delta: i64| -> Result<(), StoreError> {
        totals[index] = delta
            .checked_mul(sign)
            .and_then(|delta| totals[index].checked_add(delta))
            .ok_or(StoreError::CountOutOfRange)?;
        Ok(())
    };
    add(0, 1)?;
    for (field, value) in summary.values.iter().enumerate() {
        if let Some(value) = value {
            add(1 + field * 2, 1)?;
            add(2 + field * 2, *value)?;
        }
    }
    add(13, i64::from(summary.derived_total))?;
    add(14, i64::from(summary.mismatch))?;
    add(15, i64::from(summary.conflict))?;
    add(16, i64::from(summary.pending))?;
    match summary.consistency {
        AcquisitionConsistency::SqliteReadTransaction => add(17, 1)?,
        AcquisitionConsistency::FileByFileBestEffort => add(18, 1)?,
    }
    let assignments = PROJECTION_COLUMNS
        .iter()
        .enumerate()
        .map(|(index, name)| format!("{name} = ?{}", index + 2))
        .collect::<Vec<_>>()
        .join(", ");
    let mut parameters: Vec<&dyn rusqlite::ToSql> = vec![&summary.source_id];
    parameters.extend(totals.iter().map(|value| value as &dyn rusqlite::ToSql));
    sqlite(transaction.execute(
        &format!("UPDATE source_projection_totals SET {assignments} WHERE source_id = ?1"),
        parameters.as_slice(),
    ))?;
    Ok(())
}

/// A record's published row, read back for the projection delta.
fn load_summary(
    transaction: &Transaction<'_>,
    event_key: &str,
) -> Result<Option<EventSummary>, StoreError> {
    let row = sqlite(
        transaction
            .query_row(
                "SELECT source_id, input_tokens, output_tokens, reasoning_tokens, \
                 cache_read_tokens, cache_write_tokens, total_tokens, total_provenance, \
                 total_mismatch, mirror_conflict, pending_partial, acquisition_consistency \
                 FROM usage_events WHERE event_key = ?1",
                [event_key],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        [
                            row.get::<_, Option<i64>>(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                        ],
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, i64>(8)? != 0,
                        row.get::<_, i64>(9)? != 0,
                        row.get::<_, i64>(10)? != 0,
                        row.get::<_, String>(11)?,
                    ))
                },
            )
            .optional(),
    )?;
    row.map(
        |(source_id, values, provenance, mismatch, conflict, pending, consistency)| {
            Ok(EventSummary {
                source_id,
                values,
                derived_total: provenance.as_deref() == Some("derived"),
                mismatch,
                conflict,
                pending,
                consistency: AcquisitionConsistency::parse(&consistency)
                    .ok_or(StoreError::InvalidStoredValue)?,
            })
        },
    )
    .transpose()
}

struct WinnerRow {
    source_id: String,
    rank: i64,
    path: String,
    session_id: String,
    message_id: String,
    occurred_at_ms: i64,
    values: [Option<i64>; 6],
    provenance: Option<String>,
    convention: Option<String>,
    consistency: String,
    part_ids: String,
    pending: bool,
    reason: Option<String>,
}

/// The published row of a record: the best mirror by fixed precedence (format rank, then
/// canonical UTF-8 path bytes) across every registered source, independent of arrival order.
/// The winner and the conflict flag are resolved by two indexed queries; no mirror list is
/// materialized.
fn recompute_event(
    transaction: &Transaction<'_>,
    event_key: &str,
    now_ms: i64,
) -> Result<(), StoreError> {
    let winner = sqlite(
        transaction
            .query_row(
                "SELECT g.source_id, g.format_rank, g.mirror_path, g.session_id, g.message_id, \
                 g.occurred_at_ms, g.input_tokens, g.output_tokens, g.reasoning_tokens, \
                 g.cache_read_tokens, g.cache_write_tokens, g.total_tokens, g.total_provenance, \
                 g.source_convention, g.acquisition_consistency, g.part_ids, g.pending_partial, \
                 g.pending_reason \
                 FROM reported_groups g JOIN sources s ON s.source_id = g.source_id \
                 WHERE g.event_key = ?1 \
                 ORDER BY g.format_rank, CAST(s.canonical_root || '/' || g.mirror_path AS BLOB) \
                 LIMIT 1",
                [event_key],
                |row| {
                    Ok(WinnerRow {
                        source_id: row.get(0)?,
                        rank: row.get(1)?,
                        path: row.get(2)?,
                        session_id: row.get(3)?,
                        message_id: row.get(4)?,
                        occurred_at_ms: row.get(5)?,
                        values: [
                            row.get(6)?,
                            row.get(7)?,
                            row.get(8)?,
                            row.get(9)?,
                            row.get(10)?,
                            row.get(11)?,
                        ],
                        provenance: row.get(12)?,
                        convention: row.get(13)?,
                        consistency: row.get(14)?,
                        part_ids: row.get(15)?,
                        pending: row.get::<_, i64>(16)? != 0,
                        reason: row.get(17)?,
                    })
                },
            )
            .optional(),
    )?;
    let Some(winner) = winner else {
        return Ok(());
    };
    let provenance = winner
        .provenance
        .as_deref()
        .map(|text| parse_provenance(text).map_err(|_| StoreError::InvalidStoredValue))
        .transpose()?;
    if !total_metadata_is_valid(
        unsigned(winner.values[5])?,
        provenance,
        winner.convention.as_deref(),
    ) {
        return Err(StoreError::InvalidStoredValue);
    }
    let consistency =
        AcquisitionConsistency::parse(&winner.consistency).ok_or(StoreError::InvalidStoredValue)?;
    let components_sum = if winner.values[..5].iter().all(Option::is_some) {
        winner.values[..5]
            .iter()
            .flatten()
            .try_fold(0_i64, |sum, value| sum.checked_add(*value))
    } else {
        None
    };
    let mismatch =
        matches!((winner.values[5], components_sum), (Some(total), Some(sum)) if total != sum);
    let conflict: bool = sqlite(transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM reported_groups g WHERE g.event_key = ?1 AND NOT (\
            g.occurred_at_ms IS ?2 AND g.input_tokens IS ?3 AND g.output_tokens IS ?4 AND \
            g.reasoning_tokens IS ?5 AND g.cache_read_tokens IS ?6 AND g.cache_write_tokens IS ?7 \
            AND g.total_tokens IS ?8 AND g.part_ids IS ?9))",
        params![
            event_key,
            winner.occurred_at_ms,
            winner.values[0],
            winner.values[1],
            winner.values[2],
            winner.values[3],
            winner.values[4],
            winner.values[5],
            winner.part_ids
        ],
        |row| row.get(0),
    ))?;
    let before = load_summary(transaction, event_key)?;
    type Current = (
        String,
        String,
        i64,
        [Option<i64>; 6],
        Option<String>,
        Option<String>,
        bool,
        bool,
        String,
    );
    let changed = if before.is_none() {
        true
    } else {
        let current: Current = sqlite(transaction.query_row(
            "SELECT session_id, message_id, occurred_at_ms, input_tokens, output_tokens, \
             reasoning_tokens, cache_read_tokens, cache_write_tokens, total_tokens, \
             total_provenance, source_convention, total_mismatch, mirror_conflict, \
             selected_part_ids FROM usage_events WHERE event_key = ?1",
            [event_key],
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
                    ],
                    row.get(9)?,
                    row.get(10)?,
                    row.get::<_, i64>(11)? != 0,
                    row.get::<_, i64>(12)? != 0,
                    row.get(13)?,
                ))
            },
        ))?;
        current.0 != winner.session_id
            || current.1 != winner.message_id
            || current.2 != winner.occurred_at_ms
            || current.3 != winner.values
            || current.4 != winner.provenance
            || current.5 != winner.convention
            || current.6 != mismatch
            || current.7 != conflict
            || current.8 != winner.part_ids
    };
    if let Some(before) = &before {
        apply_summary(transaction, before, -1)?;
    }
    let pending = i64::from(winner.pending);
    if before.is_none() {
        sqlite(transaction.execute(
            "INSERT INTO usage_events(\
                event_key, family, measurement_kind, harness, source_id, session_id, message_id, \
                occurred_at_ms, input_tokens, output_tokens, reasoning_tokens, cache_read_tokens, \
                cache_write_tokens, total_tokens, total_provenance, source_convention, \
                acquisition_consistency, origin_uncertainty, total_mismatch, mirror_conflict, \
                selected_part_ids, format_rank, mirror_path, pending_partial, pending_reason, \
                revision, first_seen_ms, updated_ms\
             ) VALUES (?1, 'opencode', 'source_reported', 'opencode', ?2, ?3, ?4, ?5, ?6, ?7, ?8, \
                ?9, ?10, ?11, ?12, ?13, ?14, 'unverified_origin', ?15, ?16, ?17, ?18, ?19, ?20, ?21, 1, ?22, ?22)",
            params![
                event_key,
                winner.source_id,
                winner.session_id,
                winner.message_id,
                winner.occurred_at_ms,
                winner.values[0],
                winner.values[1],
                winner.values[2],
                winner.values[3],
                winner.values[4],
                winner.values[5],
                winner.provenance,
                winner.convention,
                consistency.as_str(),
                i64::from(mismatch),
                i64::from(conflict),
                winner.part_ids,
                winner.rank,
                winner.path,
                pending,
                winner.reason,
                now_ms,
            ],
        ))?;
    } else {
        sqlite(transaction.execute(
            "UPDATE usage_events SET source_id = ?2, session_id = ?3, message_id = ?4, \
                occurred_at_ms = ?5, input_tokens = ?6, output_tokens = ?7, reasoning_tokens = ?8, \
                cache_read_tokens = ?9, cache_write_tokens = ?10, total_tokens = ?11, \
                total_provenance = ?12, source_convention = ?13, acquisition_consistency = ?14, \
                total_mismatch = ?15, mirror_conflict = ?16, selected_part_ids = ?17, \
                format_rank = ?18, mirror_path = ?19, pending_partial = ?20, pending_reason = ?21, \
                revision = revision + ?22, \
                updated_ms = CASE WHEN ?22 = 1 THEN ?23 ELSE updated_ms END \
             WHERE event_key = ?1",
            params![
                event_key,
                winner.source_id,
                winner.session_id,
                winner.message_id,
                winner.occurred_at_ms,
                winner.values[0],
                winner.values[1],
                winner.values[2],
                winner.values[3],
                winner.values[4],
                winner.values[5],
                winner.provenance,
                winner.convention,
                consistency.as_str(),
                i64::from(mismatch),
                i64::from(conflict),
                winner.part_ids,
                winner.rank,
                winner.path,
                pending,
                winner.reason,
                i64::from(changed),
                now_ms,
            ],
        ))?;
    }
    let after = load_summary(transaction, event_key)?.ok_or(StoreError::InvalidStoredValue)?;
    apply_summary(transaction, &after, 1)
}

/// Recomputes each touched record once, after every mirror of the batch is written, so the
/// published value, conflict flag and revision never reflect a half-applied arrival order.
fn recompute_all(
    transaction: &Transaction<'_>,
    affected: &BTreeSet<String>,
    now_ms: i64,
) -> Result<(), StoreError> {
    for event_key in affected {
        recompute_event(transaction, event_key, now_ms)?;
    }
    Ok(())
}

fn publish_candidate(
    transaction: &Transaction<'_>,
    source_id: &str,
    root: &Path,
    candidate: &RecordCandidate,
    generation: u64,
    affected: &mut BTreeSet<String>,
) -> Result<CandidateWrite, StoreError> {
    validate_candidate(candidate)?;
    let event_key = candidate.record_id();
    let path = relative_text(root, &candidate.canonical_path)?;
    let rank = i64::from(candidate.format_rank);
    let selected_parts =
        serde_json::to_string(&candidate.selected_part_ids).map_err(|_| StoreError::Sqlite)?;
    let prior_parts: Option<String> = sqlite(
        transaction
            .query_row(
                "SELECT part_ids FROM reported_groups \
                 WHERE source_id = ?1 AND event_key = ?2 AND format_rank = ?3 AND mirror_path = ?4",
                params![source_id, event_key, rank, path],
                |row| row.get(0),
            )
            .optional(),
    )?;
    let withhold = candidate.pending_partial
        || prior_parts
            .as_deref()
            .is_some_and(|prior| missing_part_membership(prior, &candidate.selected_part_ids));
    let generation_sql = sql_count(generation)?;
    record_baseline(
        transaction,
        source_id,
        generation_sql,
        &event_key,
        rank,
        &path,
    )?;
    if withhold {
        if prior_parts.is_some() {
            sqlite(transaction.execute(
                "UPDATE reported_groups SET pending_partial = 1, pending_reason = ?5, generation = ?6 \
                 WHERE source_id = ?1 AND event_key = ?2 AND format_rank = ?3 AND mirror_path = ?4",
                params![
                    source_id,
                    event_key,
                    rank,
                    path,
                    FailureCode::InvalidRecord.as_str(),
                    generation_sql
                ],
            ))?;
            affected.insert(event_key);
        }
        return Ok(CandidateWrite::Pending);
    }
    let group = StoredGroup {
        session_id: candidate.session_id.clone(),
        message_id: candidate.message_id.clone(),
        occurred_at_ms: candidate.occurred_at_ms,
        values: [
            sql_optional(candidate.components.input)?,
            sql_optional(candidate.components.output)?,
            sql_optional(candidate.components.reasoning)?,
            sql_optional(candidate.components.cache_read)?,
            sql_optional(candidate.components.cache_write)?,
            sql_optional(candidate.total)?,
        ],
        total_provenance: candidate
            .total_provenance
            .map(|value| provenance_str(value).to_owned()),
        source_convention: candidate.source_convention.clone(),
        acquisition_consistency: candidate.acquisition_consistency.as_str().to_owned(),
        part_ids: selected_parts,
        pending_partial: false,
        pending_reason: None,
        generation: generation_sql,
    };
    write_group(transaction, source_id, &event_key, rank, &path, &group)?;
    affected.insert(event_key);
    Ok(CandidateWrite::Saved)
}

fn missing_part_membership(prior_json: &str, current: &[String]) -> bool {
    let Ok(prior) = serde_json::from_str::<Vec<String>>(prior_json) else {
        return true;
    };
    !prior.is_empty() && prior.iter().any(|part| !current.contains(part))
}

fn save_status(
    transaction: &Transaction<'_>,
    source_id: &str,
    outcome: PassOutcome,
    failure: Option<FailureCode>,
    counters: PassCounters,
    now_ms: i64,
    advance_last_good: bool,
) -> Result<(), StoreError> {
    sqlite(transaction.execute(
        "INSERT INTO source_status(\
            source_id, last_attempt_ms, last_success_ms, last_error_code, outcome, \
            entry_count, stat_count, header_count, directory_count, source_open_count, \
            row_count, bytes_count, rejected_count\
         ) VALUES(?1, ?2, CASE WHEN ?13 THEN ?2 ELSE NULL END, ?4, ?3, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) \
         ON CONFLICT(source_id) DO UPDATE SET \
            last_attempt_ms = excluded.last_attempt_ms, \
            last_success_ms = CASE WHEN ?13 THEN ?2 ELSE source_status.last_success_ms END, \
            last_error_code = excluded.last_error_code, outcome = excluded.outcome, \
            entry_count = excluded.entry_count, stat_count = excluded.stat_count, \
            header_count = excluded.header_count, directory_count = excluded.directory_count, \
            source_open_count = excluded.source_open_count, row_count = excluded.row_count, \
            bytes_count = excluded.bytes_count, rejected_count = excluded.rejected_count",
        params![
            source_id,
            now_ms,
            outcome.as_str(),
            failure.map(FailureCode::as_str),
            sql_count(u64::from(counters.entries))?,
            sql_count(u64::from(counters.stat_calls))?,
            sql_count(u64::from(counters.header_reads))?,
            sql_count(u64::from(counters.directory_opens))?,
            sql_count(u64::from(counters.source_opens))?,
            sql_count(u64::from(counters.rows_read))?,
            sql_count(counters.bytes_read)?,
            sql_count(u64::from(counters.rejected_records))?,
            advance_last_good,
        ],
    ))?;
    Ok(())
}

/// One persisted record decoded and validated: any unknown code or relational contradiction is
/// an explicit stored-value error, never a silent default.
fn observation_from_row(
    source_id: &str,
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<SourceReportedObservation, StoreError>> {
    let part_ids: String = row.get(15)?;
    let pending_partial = row.get::<_, i64>(16)? == 1;
    let pending_reason: Option<String> = row.get(17)?;
    let provenance: Option<String> = row.get(10)?;
    let convention: Option<String> = row.get(11)?;
    let consistency: String = row.get(18)?;
    let raw = [
        row.get::<_, Option<i64>>(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
    ];
    let record_id: String = row.get(0)?;
    let session_id: String = row.get(1)?;
    let message_id: String = row.get(2)?;
    let occurred_at_ms: i64 = row.get(3)?;
    let mismatch = row.get::<_, i64>(12)? != 0;
    let conflict = row.get::<_, i64>(13)? != 0;
    let revision: i64 = row.get(14)?;
    let decoded = (|| {
        let provenance = provenance
            .as_deref()
            .map(|text| parse_provenance(text).map_err(|_| StoreError::InvalidStoredValue))
            .transpose()?;
        if !total_metadata_is_valid(unsigned(raw[5])?, provenance, convention.as_deref()) {
            return Err(StoreError::InvalidStoredValue);
        }
        let pending_reason = match pending_reason.as_deref() {
            None => None,
            Some(text) => Some(FailureCode::parse(text).ok_or(StoreError::InvalidStoredValue)?),
        };
        if pending_reason.is_some() && !pending_partial {
            return Err(StoreError::InvalidStoredValue);
        }
        let observation = |value: Option<i64>, provenance: Option<Provenance>| {
            let value = unsigned(value)?;
            if value.is_some_and(|value| value > MAX_TOKEN_COUNT) {
                return Err(StoreError::CountOutOfRange);
            }
            Ok::<_, StoreError>(TokenObservation {
                value,
                unit: TokenUnit::Tokens,
                provenance: value.and(provenance),
                status: match (value, pending_partial) {
                    (Some(_), false) => ObservationStatus::Current,
                    (Some(_), true) => ObservationStatus::Partial,
                    (None, _) => ObservationStatus::Unavailable,
                },
            })
        };
        let record = SourceReportedObservation {
            source_id: source_id.to_owned(),
            record_id,
            session_id,
            message_id,
            occurred_at_ms,
            input: observation(raw[0], Some(Provenance::Reported))?,
            output: observation(raw[1], Some(Provenance::Reported))?,
            reasoning: observation(raw[2], Some(Provenance::Reported))?,
            cache_read: observation(raw[3], Some(Provenance::Reported))?,
            cache_write: observation(raw[4], Some(Provenance::Reported))?,
            total: observation(raw[5], provenance)?,
            source_convention: convention.clone(),
            acquisition_consistency: AcquisitionConsistency::parse(&consistency)
                .ok_or(StoreError::InvalidStoredValue)?,
            origin_uncertainty: OriginUncertainty::UnverifiedOrigin,
            total_mismatch: mismatch,
            mirror_conflict: conflict,
            selected_part_ids: decode_part_ids(&part_ids)?,
            revision: u64::try_from(revision).map_err(|_| StoreError::InvalidStoredValue)?,
            pending_partial,
            pending_reason,
        };
        record
            .validate()
            .map_err(|_| StoreError::InvalidStoredValue)?;
        Ok(record)
    })();
    Ok(decoded)
}

/// A persisted selected-part list decoded under the producer's element and byte bounds; the
/// text must hold exactly one such list.
fn decode_part_ids(text: &str) -> Result<Vec<String>, StoreError> {
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let parts = crate::domain::bounded::part_ids(&mut deserializer)
        .map_err(|_| StoreError::InvalidStoredValue)?;
    deserializer
        .end()
        .map_err(|_| StoreError::InvalidStoredValue)?;
    Ok(parts)
}

const FIRST_PAGE_SQL: &str = "SELECT event_key, session_id, message_id, occurred_at_ms, \
     input_tokens, output_tokens, reasoning_tokens, cache_read_tokens, cache_write_tokens, \
     total_tokens, total_provenance, source_convention, total_mismatch, mirror_conflict, \
     revision, selected_part_ids, pending_partial, pending_reason, acquisition_consistency \
     FROM usage_events WHERE source_id = ?1 ORDER BY occurred_at_ms, event_key LIMIT ?2";

/// Later pages seek the `(source_id, occurred_at_ms, event_key)` index at the cursor tuple.
const NEXT_PAGE_SQL: &str = "SELECT event_key, session_id, message_id, occurred_at_ms, \
     input_tokens, output_tokens, reasoning_tokens, cache_read_tokens, cache_write_tokens, \
     total_tokens, total_provenance, source_convention, total_mismatch, mirror_conflict, \
     revision, selected_part_ids, pending_partial, pending_reason, acquisition_consistency \
     FROM usage_events WHERE source_id = ?1 AND (occurred_at_ms, event_key) > (?3, ?4) \
     ORDER BY occurred_at_ms, event_key LIMIT ?2";

/// SQL text of the history page queries, exposed so tests can inspect their plans.
pub fn history_page_sql(after_cursor: bool) -> &'static str {
    if after_cursor {
        NEXT_PAGE_SQL
    } else {
        FIRST_PAGE_SQL
    }
}

impl Store {
    /// All durable records of a source when they fit one bounded page; otherwise
    /// `LimitExceeded`, never a silent truncation. Larger histories are read with
    /// [`Store::observations_page`].
    pub fn observations(
        &self,
        source_id: &str,
    ) -> Result<Vec<SourceReportedObservation>, StoreError> {
        let page = self.observations_page(source_id, None, MAX_OBSERVATION_PAGE)?;
        if page.next.is_some() {
            return Err(StoreError::LimitExceeded);
        }
        Ok(page.observations)
    }

    /// One page of raw durable records in `(occurred_at_ms, record_id)` order.
    pub fn observations_page(
        &self,
        source_id: &str,
        after: Option<&ObservationCursor>,
        limit: usize,
    ) -> Result<ObservationPage, StoreError> {
        let limit = limit.clamp(1, MAX_OBSERVATION_PAGE);
        let fetch = i64::try_from(limit + 1).unwrap_or(i64::MAX);
        let rows = if let Some(cursor) = after {
            if !cursor.is_valid() {
                return Err(StoreError::InvalidStoredValue);
            }
            let mut statement = sqlite(self.connection.prepare(NEXT_PAGE_SQL))?;
            let rows = sqlite(statement.query_map(
                params![source_id, fetch, cursor.occurred_at_ms, cursor.record_id],
                |row| observation_from_row(source_id, row),
            ))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
        } else {
            let mut statement = sqlite(self.connection.prepare(FIRST_PAGE_SQL))?;
            let rows = sqlite(statement.query_map(params![source_id, fetch], |row| {
                observation_from_row(source_id, row)
            }))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
        };
        let mut observations = Vec::new();
        for row in rows.map_err(|_| StoreError::Sqlite)? {
            observations.push(row?);
        }
        let next = if observations.len() > limit {
            observations.truncate(limit);
            observations.last().map(|last| ObservationCursor {
                occurred_at_ms: last.occurred_at_ms,
                record_id: last.record_id.clone(),
            })
        } else {
            None
        };
        Ok(ObservationPage { observations, next })
    }

    /// Checked per-source sums over every durable record, with missing values kept distinct from
    /// zero: a component absent from some records is `partial`, absent from all is `unavailable`.
    /// Read from the projection maintained in the same transactions that write the records.
    pub fn source_projection(&self, source_id: &str) -> Result<SourceProjection, StoreError> {
        let totals = projection_totals(&self.connection, source_id)?.unwrap_or([0; 19]);
        validate_totals(&totals)?;
        let records = totals[0];
        let pending = totals[16] > 0;
        let aggregate = |field: usize, provenance: Option<Provenance>| {
            let (present, sum) = (totals[1 + field * 2], totals[2 + field * 2]);
            if present == 0 {
                return Ok(unavailable());
            }
            let value = u64::try_from(sum).map_err(|_| StoreError::InvalidStoredValue)?;
            Ok::<_, StoreError>(TokenObservation {
                value: Some(value),
                unit: TokenUnit::Tokens,
                provenance,
                status: if present < records || pending {
                    ObservationStatus::Partial
                } else {
                    ObservationStatus::Current
                },
            })
        };
        let derived = totals[13] > 0;
        let consistency = match (records, totals[17] > 0, totals[18] > 0) {
            (0, _, _) => None,
            (_, true, true) => Some(ProjectionConsistency::Mixed),
            (_, true, false) => Some(ProjectionConsistency::SqliteReadTransaction),
            (_, false, _) => Some(ProjectionConsistency::FileByFileBestEffort),
        };
        let projection = SourceProjection {
            records: u64::try_from(records).map_err(|_| StoreError::InvalidStoredValue)?,
            input: aggregate(0, Some(Provenance::Reported))?,
            output: aggregate(1, Some(Provenance::Reported))?,
            reasoning: aggregate(2, Some(Provenance::Reported))?,
            cache_read: aggregate(3, Some(Provenance::Reported))?,
            cache_write: aggregate(4, Some(Provenance::Reported))?,
            total: aggregate(
                5,
                Some(if derived {
                    Provenance::Derived
                } else {
                    Provenance::Reported
                }),
            )?,
            source_convention: (derived && totals[11] > 0)
                .then(|| OPENCODE_SOURCE_CONVENTION.to_owned()),
            acquisition_consistency: consistency,
            origin_uncertainty: OriginUncertainty::UnverifiedOrigin,
            total_mismatch: totals[14] > 0,
            mirror_conflict: totals[15] > 0,
            pending_partial: pending,
        };
        projection
            .validate()
            .map_err(|_| StoreError::InvalidStoredValue)?;
        Ok(projection)
    }

    pub fn last_success_ms(&self, source_id: &str) -> Result<Option<i64>, StoreError> {
        let timestamp = sqlite(
            self.connection
                .query_row(
                    "SELECT last_success_ms FROM source_status WHERE source_id = ?1",
                    [source_id],
                    |row| row.get::<_, Option<i64>>(0),
                )
                .optional(),
        )?;
        Ok(timestamp.flatten())
    }

    pub fn source_id(&self, canonical_root: &Path) -> Result<Option<String>, StoreError> {
        let root = canonical_root.to_str().ok_or(StoreError::InvalidRoot)?;
        sqlite(
            self.connection
                .query_row(
                    "SELECT source_id FROM sources WHERE canonical_root = ?1",
                    [root],
                    |row| row.get(0),
                )
                .optional(),
        )
    }
}

/// Maintained-counter algebra: every counter is non-negative and bounded by what the record
/// count and the raw-record ceiling permit, presence counts never exceed records, zero presence
/// carries a zero sum, derived totals are a subset of present totals, and the two acquisition
/// methods partition the records exactly.
fn validate_totals(totals: &[i64; 19]) -> Result<(), StoreError> {
    let records = totals[0];
    if totals.iter().any(|value| *value < 0) {
        return Err(StoreError::InvalidStoredValue);
    }
    for field in 0..6 {
        let (present, sum) = (totals[1 + field * 2], totals[2 + field * 2]);
        let ceiling = i128::from(present) * i128::from(MAX_TOKEN_COUNT);
        if present > records || i128::from(sum) > ceiling {
            return Err(StoreError::InvalidStoredValue);
        }
    }
    let (derived, mismatch, conflict, pending) = (totals[13], totals[14], totals[15], totals[16]);
    if derived > totals[11]
        || mismatch > records
        || conflict > records
        || pending > records
        || totals[17].checked_add(totals[18]) != Some(records)
    {
        return Err(StoreError::InvalidStoredValue);
    }
    Ok(())
}

fn unavailable() -> TokenObservation {
    TokenObservation {
        value: None,
        unit: TokenUnit::Tokens,
        provenance: None,
        status: ObservationStatus::Unavailable,
    }
}

fn parse_provenance(value: &str) -> rusqlite::Result<Provenance> {
    match value {
        "reported" => Ok(Provenance::Reported),
        "derived" => Ok(Provenance::Derived),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn provenance_str(value: Provenance) -> &'static str {
    match value {
        Provenance::Reported => "reported",
        Provenance::Derived => "derived",
    }
}

fn sql_optional(value: Option<u64>) -> Result<Option<i64>, StoreError> {
    value.map(sql_count).transpose()
}

fn sql_count(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::CountOutOfRange)
}

impl PassOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Consistent => "consistent",
            Self::CatchingUp => "catching_up",
            Self::Partial => "partial",
            Self::Unavailable => "unavailable",
        }
    }
}

impl ConsentState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Undecided => "undecided",
            Self::Enabled => "enabled",
            Self::Denied => "denied",
        }
    }
}

impl SpoolCandidate {
    fn from_record(record: &RecordCandidate, relative_path: String) -> Self {
        Self {
            relative_path,
            session_id: record.session_id.clone(),
            message_id: record.message_id.clone(),
            occurred_at_ms: record.occurred_at_ms,
            components: record.components.clone(),
            total: record.total,
            total_provenance: record.total_provenance,
            source_convention: record.source_convention.clone(),
            acquisition_consistency: record.acquisition_consistency,
            selected_part_ids: record.selected_part_ids.clone(),
            pending_partial: record.pending_partial,
            format_rank: record.format_rank,
            fingerprint: record.fingerprint,
        }
    }

    fn into_record(self, root: &Path) -> Result<RecordCandidate, StoreError> {
        let relative_path = checked_relative_path(&self.relative_path)?;
        let record = RecordCandidate {
            session_id: self.session_id,
            message_id: self.message_id,
            occurred_at_ms: self.occurred_at_ms,
            components: self.components,
            total: self.total,
            total_provenance: self.total_provenance,
            source_convention: self.source_convention,
            acquisition_consistency: self.acquisition_consistency,
            selected_part_ids: self.selected_part_ids,
            pending_partial: self.pending_partial,
            canonical_path: root.join(relative_path),
            format_rank: self.format_rank,
            fingerprint: self.fingerprint,
        };
        validate_candidate(&record)?;
        Ok(record)
    }
}

fn relative_text(root: &Path, path: &Path) -> Result<String, StoreError> {
    let relative = if path.is_absolute() {
        path.strip_prefix(root)
            .map_err(|_| StoreError::InvalidRelativePath)?
    } else {
        path
    };
    let text = relative.to_str().ok_or(StoreError::InvalidRelativePath)?;
    let checked = checked_relative_path(text)?;
    if checked.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES {
        return Err(StoreError::InvalidRelativePath);
    }
    Ok(text.to_owned())
}

fn checked_relative_path(path: &str) -> Result<PathBuf, StoreError> {
    let path = Path::new(path);
    if path.is_absolute()
        || path.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(StoreError::InvalidRelativePath);
    }
    Ok(path.to_path_buf())
}
