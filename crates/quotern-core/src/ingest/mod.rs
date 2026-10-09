pub mod fs;
pub mod jsonl;
pub mod sqlite_ro;

/// The most one file read may return: the per-record ceiling, and never more than the lane has
/// left of its byte allowance, so the read is bounded before any byte is requested.
fn read_allowance(lane: Lane, counters: &PassCounters) -> usize {
    let left = lane.bytes().saturating_sub(counters.bytes_read);
    usize::try_from(left)
        .unwrap_or(usize::MAX)
        .min(MAX_OPENCODE_RECORD_BYTES)
}

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use crate::adapters::codex::CodexSource;
use crate::adapters::opencode::StepFinishPart;
use crate::adapters::opencode::{self, DecodeError, ReadBudget, ResolveError};
use crate::discovery::{self, CanonicalRoots, DataAnchor, RootError};
use crate::domain::{
    ConsentState, FailureCode, Harness, PassCounters, PassOutcome, PassReport, RecordCandidate,
    SourceAuthorization, SourceKind, SourceReportedObservation,
};
use crate::limits::{
    MAX_DIRECTORY_DEPTH, MAX_DIRECTORY_ENTRIES, MAX_DIRECTORY_OPENS, MAX_FRONTIER_DIRECTORIES,
    MAX_HEADER_READS, MAX_KNOWN_PATHS_PER_PASS, MAX_METADATA_CALLS, MAX_OPEN_DIRECTORIES,
    MAX_OPENCODE_RECORD_BYTES, MAX_PATH_BYTES, MAX_REPORTED_SOURCES, MAX_SOURCE_BYTES_PER_PASS,
    MAX_SOURCE_DATABASES_PER_PASS, MAX_SQLITE_ROWS_PER_PASS,
};
use crate::snapshot::{
    DailyReported, ObservationCursor, ObservationPage, SourceEntry, SourceSnapshot, TodaySnapshot,
    Window, WindowError,
};
use crate::store::{
    CommitRequest, DataDirOwner, DiscardRequest, FileFailure, PendingMark, ProgressUpdate,
    SourceRow, SpoolFile, StageBatch, StageRequest, Store, StoreError, retry_outcome,
};

use self::fs::{DirEntries, FileStamp, SourceFs, budget_exhausted};

/// Iterator slots held by the directory frontier; the synchronous JSON-part iterator is the
/// remaining one of `MAX_OPEN_DIRECTORIES`, so held iterators never exceed the ceiling.
const FRONTIER_SLOTS: usize = MAX_OPEN_DIRECTORIES - 1;

/// Metadata calls kept back from a database read for the four-sidecar identity proof after it.
const IDENTITY_PROOF_STATS: u32 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RootIdentity {
    pub(crate) device: u64,
    pub(crate) inode: u64,
}

/// Why a unit of work stopped: the shared per-pass budget ended (resume later) or a real failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Stop {
    Budget,
    ValidationBudget,
    Fail(FailureCode),
}

/// Operation budget of one traversal lane. The reserved current-file lane gets half of every
/// ceiling while a historical backlog exists; the historical lane may use the full ceiling, so
/// whatever the current lane leaves unused transfers to it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Lane {
    Current,
    Full,
}

impl Lane {
    fn divisor(self) -> u32 {
        match self {
            Self::Current => 2,
            Self::Full => 1,
        }
    }

    fn rows(self) -> u32 {
        MAX_SQLITE_ROWS_PER_PASS / self.divisor()
    }

    pub(crate) fn bytes(self) -> u64 {
        MAX_SOURCE_BYTES_PER_PASS / u64::from(self.divisor())
    }

    /// Whether this lane may still open another directory.
    pub(crate) fn opens_exhausted(self, counters: &PassCounters) -> bool {
        counters.directory_opens >= MAX_DIRECTORY_OPENS / self.divisor()
    }

    /// Whether the per-operation ceilings (everything but directory opens) are used up. Work on
    /// a directory that is already open is limited by these only.
    fn operations_exhausted(self, counters: &PassCounters) -> bool {
        let divisor = self.divisor();
        counters.entries >= MAX_DIRECTORY_ENTRIES / divisor
            || counters.stat_calls >= MAX_METADATA_CALLS / divisor
            || counters.header_reads >= MAX_HEADER_READS / divisor
            || counters.rows_read >= self.rows()
            || counters.bytes_read >= self.bytes()
    }

    /// The reserved current lane also stops at its half of the directory opens; the historical
    /// lane meets that ceiling in the frontier itself.
    pub(crate) fn exhausted(self, counters: &PassCounters) -> bool {
        self.operations_exhausted(counters)
            || (self == Self::Current && self.opens_exhausted(counters))
    }
}

pub(crate) struct DirectoryWork {
    pub(crate) path: PathBuf,
    pub(crate) depth: usize,
    pub(crate) stat: Option<SpoolFile>,
    pub(crate) restart_blocked: bool,
}

struct ActiveDirectory {
    path: PathBuf,
    depth: usize,
    entries: DirEntries,
    stat: SpoolFile,
    entries_read: u32,
    retry: bool,
}

/// A yielded directory entry. `replay` marks one already counted in an earlier pass.
pub(crate) struct Entry {
    pub(crate) path: PathBuf,
    pub(crate) depth: usize,
    replay: bool,
}

pub(crate) enum WalkStep {
    Entry(Entry),
    CompletedDirectory(SpoolFile),
    /// A directory could not be listed or described; its retry stays in the frontier.
    Error(FailureCode),
    Capped,
    Exhausted,
}

/// A directory whose iterator reached EOF while the part scan of one of its messages was still
/// held. That scan lives only in memory and its message is no source file until the group is
/// finished, so the directory keeps the queue slot it held while active (and its durable pending
/// row) until the scan ends, and is listed again from its beginning after a restart.
struct ParkedDirectory {
    work: DirectoryWork,
    message: PathBuf,
}

pub(crate) struct DirectoryFrontier {
    root: PathBuf,
    pending: VecDeque<DirectoryWork>,
    failed: Vec<DirectoryWork>,
    active: Vec<ActiveDirectory>,
    scheduled: HashSet<PathBuf>,
    completed: HashSet<PathBuf>,
    /// The one entry whose processing ran out of budget; it is replayed first next pass, so no
    /// directory is re-listed and no entry is lost.
    deferred: Option<Entry>,
    turn: usize,
    /// Index in `active` of the directory that yielded the latest entry; nothing reorders
    /// `active` between a yield and the replay or visit of that entry.
    source: usize,
    capped: bool,
    restart_blocked: bool,
    pub(crate) validation_budget: bool,
    pub(crate) validation_retry: bool,
    /// Exhausted directories kept pending for a held part scan; they count against the queue
    /// ceiling exactly as they did while active.
    parked: Vec<ParkedDirectory>,
}

impl DirectoryFrontier {
    pub(crate) fn new(
        root: &Path,
        pending: Vec<(PathBuf, usize, bool)>,
        completed: Vec<PathBuf>,
    ) -> Self {
        let mut frontier = Self {
            root: root.to_path_buf(),
            pending: VecDeque::new(),
            failed: Vec::new(),
            active: Vec::new(),
            scheduled: HashSet::new(),
            completed: completed.into_iter().collect(),
            deferred: None,
            turn: 0,
            source: 0,
            capped: false,
            parked: Vec::new(),
            restart_blocked: false,
            validation_budget: false,
            validation_retry: false,
        };
        // A directory that is still pending was persisted complete earlier but must be listed
        // again (its held part scan was lost with the process): pending wins over completed.
        for (path, ..) in &pending {
            frontier.completed.remove(path);
        }
        for path in frontier.completed.iter() {
            frontier.scheduled.insert(path.clone());
        }
        for (path, depth, restart_blocked) in pending {
            frontier.enqueue(DirectoryWork {
                path,
                depth,
                stat: None,
                restart_blocked,
            });
        }
        frontier.queue_root();
        frontier
    }

    // An absent root witness requires rediscovery. A full queue retains every child; the root
    // takes the first free slot instead of exceeding the cap or replacing pending work.
    fn queue_root(&mut self) {
        if !self.scheduled.contains(&self.root)
            && self.pending.len() + self.active.len() + self.parked.len() + self.failed.len()
                < MAX_FRONTIER_DIRECTORIES
        {
            self.enqueue(DirectoryWork {
                path: self.root.clone(),
                depth: 0,
                stat: None,
                restart_blocked: false,
            });
        }
    }

    pub(crate) fn begin_pass(&mut self) {
        self.capped = false;
        self.validation_budget = false;
        self.validation_retry = false;
        self.pending.extend(self.failed.drain(..));
    }

    pub(crate) fn enqueue(&mut self, work: DirectoryWork) -> bool {
        if work.restart_blocked {
            self.restart_blocked = true;
        }
        if self.completed.contains(&work.path) || self.scheduled.contains(&work.path) {
            return true;
        }
        if self.pending.len() + self.active.len() + self.parked.len() + self.failed.len()
            >= MAX_FRONTIER_DIRECTORIES
        {
            self.capped = true;
            return false;
        }
        self.scheduled.insert(work.path.clone());
        self.pending.push_back(work);
        true
    }

    pub(crate) fn defer(&mut self, mut entry: Entry) {
        entry.replay = true;
        self.deferred = Some(entry);
    }

    /// The queue ceiling refused a child of the directory that yielded the latest entry. That
    /// listing goes to the back of the queue, in place (the combined count is unchanged), and is
    /// read again from its beginning once the directories ahead of it have drained, so the child
    /// and every later sibling are found when room exists instead of being dropped.
    pub(crate) fn requeue_source(&mut self) {
        if self.source >= self.active.len() {
            return;
        }
        let active = self.active.remove(self.source);
        self.turn = 0;
        self.pending.push_back(DirectoryWork {
            path: active.path,
            depth: active.depth,
            stat: Some(active.stat),
            restart_blocked: false,
        });
    }

    pub(crate) fn retry_source(&mut self) {
        if let Some(active) = self.active.get_mut(self.source) {
            active.retry = true;
        }
    }

    fn mark_complete(&mut self, path: PathBuf) {
        self.completed.insert(path.clone());
        self.scheduled.insert(path);
    }

    pub(crate) fn retry_unverified_directories(&mut self, files: &[SpoolFile]) {
        let paths: Vec<PathBuf> = std::iter::once(self.root.clone())
            .chain(
                files
                    .iter()
                    .filter(|file| file.parser_kind == "directory")
                    .map(|file| self.root.join(&file.relative_path)),
            )
            .collect();
        for path in paths {
            if self.completed.remove(&path) {
                self.scheduled.remove(&path);
                let depth = path
                    .strip_prefix(&self.root)
                    .map_or(0, |relative| relative.components().count());
                if self.pending.len() + self.active.len() + self.parked.len() + self.failed.len()
                    < MAX_FRONTIER_DIRECTORIES
                {
                    self.enqueue(DirectoryWork {
                        path,
                        depth,
                        stat: None,
                        restart_blocked: false,
                    });
                } else {
                    for ancestor in path
                        .ancestors()
                        .skip(1)
                        .take_while(|ancestor| ancestor.starts_with(&self.root))
                    {
                        if self.completed.remove(ancestor) {
                            self.scheduled.remove(ancestor);
                        }
                    }
                }
            }
        }
        // If every slot is occupied, the absent root witness schedules rediscovery when one drains.
        self.queue_root();
    }

    pub(crate) fn snapshot(&self) -> Vec<(PathBuf, usize, bool)> {
        let mut directories =
            Vec::with_capacity(self.pending.len() + self.active.len() + self.parked.len());
        directories.extend(
            self.pending
                .iter()
                .map(|work| (work.path.clone(), work.depth, work.restart_blocked)),
        );
        directories.extend(
            self.failed
                .iter()
                .map(|work| (work.path.clone(), work.depth, work.restart_blocked)),
        );
        directories.extend(self.active.iter().map(|active| {
            (
                active.path.clone(),
                active.depth,
                !self.capped && active.entries_read > 0,
            )
        }));
        directories.extend(
            self.parked
                .iter()
                .map(|parked| (parked.work.path.clone(), parked.work.depth, false)),
        );
        directories
    }

    pub(crate) fn is_drained(&self) -> bool {
        self.pending.is_empty()
            && self.failed.is_empty()
            && self.active.is_empty()
            && self.parked.is_empty()
            && self.deferred.is_none()
            && !self.capped
    }

    /// Completes every parked directory whose message is no longer the one scan being held.
    fn release_parked(&mut self, held: Option<&Path>) {
        let (kept, released): (Vec<_>, Vec<_>) = std::mem::take(&mut self.parked)
            .into_iter()
            .partition(|parked| held == Some(parked.message.as_path()));
        self.parked = kept;
        for parked in released {
            self.completed.insert(parked.work.path);
        }
    }

    pub(crate) fn source_metadata_if_present<F: SourceFs>(
        fs: &F,
        roots: &CanonicalRoots,
        expected: RootIdentity,
        path: &Path,
        counters: &mut PassCounters,
    ) -> Result<Option<std::fs::Metadata>, Stop> {
        let metadata = stat_optional(fs, path, counters)?;
        if path == roots.source
            && metadata.as_ref().is_some_and(|root| {
                !root.is_dir() || root.dev() != expected.device || root.ino() != expected.inode
            })
        {
            return Err(Stop::Fail(FailureCode::RootOverlap));
        }
        if metadata.is_none() {
            // Only child pruning is terminal; a lost source root must remain a visible failure.
            if path == roots.source {
                return Err(Stop::Fail(FailureCode::SourceChanging));
            }
            let root = source_metadata(fs, &roots.source, counters).map_err(|stop| match stop {
                Stop::Budget => Stop::ValidationBudget,
                other => other,
            })?;
            if !root.is_dir() || root.dev() != expected.device || root.ino() != expected.inode {
                return Err(Stop::Fail(FailureCode::RootOverlap));
            }
        }
        Ok(metadata)
    }

    /// `held` is the message whose part scan is held open: its parent directory is parked, not
    /// completed, when its iterator ends.
    pub(crate) fn next<F: SourceFs>(
        &mut self,
        fs: &F,
        roots: &CanonicalRoots,
        source_identity: RootIdentity,
        held: Option<&Path>,
        counters: &mut PassCounters,
    ) -> WalkStep {
        self.queue_root();
        if let Some(entry) = self.deferred.take() {
            return WalkStep::Entry(entry);
        }
        if self.capped {
            return WalkStep::Capped;
        }
        while self.active.len() < FRONTIER_SLOTS && !self.pending.is_empty() {
            if counters.directory_opens >= MAX_DIRECTORY_OPENS {
                self.capped = true;
                return WalkStep::Capped;
            }
            let Some(mut work) = self.pending.pop_front() else {
                break;
            };
            if work.depth > MAX_DIRECTORY_DEPTH {
                self.pending.push_front(work);
                self.capped = true;
                return WalkStep::Capped;
            }
            let stat = match work.stat.take() {
                Some(stat) => stat,
                None => match Self::source_metadata_if_present(
                    fs,
                    roots,
                    source_identity,
                    &work.path,
                    counters,
                ) {
                    Ok(Some(metadata)) if metadata.is_dir() => {
                        match spool_file(roots, &work.path, &metadata, "directory") {
                            Ok(stat) => stat,
                            Err(code) => {
                                self.failed.push(work);
                                return WalkStep::Error(code);
                            }
                        }
                    }
                    Ok(_) => {
                        self.scheduled.remove(&work.path);
                        continue;
                    }
                    Err(stop @ (Stop::Budget | Stop::ValidationBudget)) => {
                        self.validation_budget |= stop == Stop::ValidationBudget;
                        self.validation_retry |= stop == Stop::ValidationBudget;
                        self.pending.push_front(work);
                        self.capped = true;
                        return WalkStep::Capped;
                    }
                    Err(Stop::Fail(code)) => {
                        self.failed.push(work);
                        return WalkStep::Error(code);
                    }
                },
            };
            counters.directory_opens = counters.directory_opens.saturating_add(1);
            match fs.read_dir_selected(
                &work.path,
                FileStamp {
                    device: stat.device,
                    inode: stat.inode,
                    size: stat.size,
                    mtime_ns: stat.mtime_ns,
                },
                counters,
            ) {
                Ok(entries) => self.active.push(ActiveDirectory {
                    path: work.path,
                    depth: work.depth,
                    entries,
                    stat,
                    entries_read: 0,
                    retry: false,
                }),
                Err(error) if budget_exhausted(&error) => {
                    self.validation_budget |= fs::validation_budget_exhausted(&error);
                    self.validation_retry |= fs::validation_budget_exhausted(&error);
                    self.pending.push_front(work);
                    self.capped = true;
                    return WalkStep::Capped;
                }
                Err(error) => {
                    // A cached directory stamp cannot distinguish pruning from a listing failure.
                    if error.kind() == io::ErrorKind::NotFound {
                        match Self::source_metadata_if_present(
                            fs,
                            roots,
                            source_identity,
                            &work.path,
                            counters,
                        ) {
                            Ok(None) => {
                                self.scheduled.remove(&work.path);
                                continue;
                            }
                            Err(Stop::Budget | Stop::ValidationBudget) => {
                                self.validation_budget = true;
                                self.validation_retry = true;
                                work.stat = Some(stat);
                                self.pending.push_front(work);
                                self.capped = true;
                                return WalkStep::Capped;
                            }
                            Err(Stop::Fail(code)) => {
                                work.stat = None;
                                self.failed.push(work);
                                return WalkStep::Error(code);
                            }
                            Ok(_) => {}
                        }
                    }
                    work.stat = (error.kind() != io::ErrorKind::NotFound).then_some(stat);
                    self.failed.push(work);
                    return WalkStep::Error(io_failure(error));
                }
            }
        }
        if self.active.is_empty() {
            self.queue_root();
            return if self.pending.is_empty() {
                WalkStep::Exhausted
            } else {
                WalkStep::Capped
            };
        }
        let index = self.turn % self.active.len();
        match self.active[index].entries.next() {
            Some(Ok(path)) => {
                // Every yield is charged the moment it is pulled.
                counters.entries = counters.entries.saturating_add(1);
                self.active[index].entries_read = self.active[index].entries_read.saturating_add(1);
                let depth = self.active[index].depth;
                self.turn = (index + 1) % self.active.len();
                self.source = index;
                WalkStep::Entry(Entry {
                    path,
                    depth,
                    replay: false,
                })
            }
            Some(Err(error)) => {
                counters.entries = counters.entries.saturating_add(1);
                let active = self.active.remove(index);
                self.failed.push(DirectoryWork {
                    path: active.path,
                    depth: active.depth,
                    stat: Some(active.stat),
                    restart_blocked: false,
                });
                self.turn = 0;
                WalkStep::Error(io_failure(error))
            }
            None => {
                let active = self.active.remove(index);
                self.turn = 0;
                if active.retry {
                    self.failed.push(DirectoryWork {
                        path: active.path,
                        depth: active.depth,
                        stat: None,
                        restart_blocked: false,
                    });
                    return WalkStep::Capped;
                }
                if let Some(message) =
                    held.filter(|message| message.parent() == Some(active.path.as_path()))
                {
                    self.parked.push(ParkedDirectory {
                        work: DirectoryWork {
                            path: active.path,
                            depth: active.depth,
                            stat: None,
                            restart_blocked: false,
                        },
                        message: message.to_path_buf(),
                    });
                } else {
                    self.completed.insert(active.path);
                }
                WalkStep::CompletedDirectory(active.stat)
            }
        }
    }
}

/// Everything one pass gathers before it is written in a single store transaction.
#[derive(Default)]
struct PassState<'a> {
    counters: PassCounters,
    candidates: Vec<RecordCandidate>,
    files: Vec<SpoolFile>,
    verified_files: usize,
    progress: Vec<ProgressUpdate>,
    failed: Vec<FileFailure>,
    recovered: Vec<PathBuf>,
    pending: Vec<PendingMark>,
    visited: HashSet<PathBuf>,
    /// Known files revalidated by the current lane, so the next pass rotates to the others.
    revalidated: Vec<PathBuf>,
    database_opens: u32,
    /// Best record-level rejection (deterministic: smallest code name).
    rejection: Option<FailureCode>,
    /// Best failure of an entry that was skipped rather than read (symlink, path limit, â¦).
    skipped: Option<FailureCode>,
    source_seen: bool,
    stable_read: bool,
    caught_up: bool,
    incomplete: bool,
    /// The reserved current lane ended with work left (a bounded slice or the lane's budget). It
    /// keeps the pass catching up but never stops the historical lane, which still owns the rest
    /// of the budget.
    current_incomplete: bool,
    changing: bool,
    changing_path: Option<PathBuf>,
    cancel: Option<&'a AtomicBool>,
    cancelled: bool,
}

pub(crate) fn lesser(current: Option<FailureCode>, code: FailureCode) -> Option<FailureCode> {
    match current {
        Some(existing) if existing.as_str() <= code.as_str() => Some(existing),
        _ => Some(code),
    }
}

impl PassState<'_> {
    /// Whether the cancel flag is set. Called only where the pass already polls its budget, so
    /// a cancel stops the pass exactly as a budget stop does.
    fn cancel_requested(&mut self) -> bool {
        if self
            .cancel
            .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Acquire))
        {
            self.cancelled = true;
        }
        self.cancelled
    }

    fn reject(&mut self, code: FailureCode) {
        self.rejection = lesser(self.rejection, code);
    }

    fn skip(&mut self, code: FailureCode) {
        self.skipped = match (self.skipped, code) {
            (Some(FailureCode::RootOverlap), _) | (_, FailureCode::RootOverlap) => {
                Some(FailureCode::RootOverlap)
            }
            (current, code) => lesser(current, code),
        };
        self.incomplete = true;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RootCheck {
    Valid,
    Budget,
    Conflict,
}

/// Result of processing one source file.
enum FileOutcome {
    /// Read. `rejected` is a record-level rejection; `more` means a bounded slice remains.
    Done {
        rejected: Option<FailureCode>,
        more: bool,
    },
    Failed(FailureCode),
    Changing,
    Budget,
    Skipped,
}

struct OpenCodeSource<F: SourceFs> {
    fs: F,
    source_request: PathBuf,
    data_request: PathBuf,
    home: PathBuf,
    roots: CanonicalRoots,
    source_identity: RootIdentity,
    data_identity: RootIdentity,
    source_id: String,
    generation: u64,
    frontier: DirectoryFrontier,
    /// Durable per-file acquisition failures, retried apart from directory traversal.
    failures: BTreeMap<PathBuf, FailureCode>,
    /// In-memory acquisition state no longer matches the store and must be reloaded first.
    needs_reload: bool,
    /// A finalization failed: staged acquisition evidence must be dropped before it is trusted.
    needs_reset: bool,
    /// The JSON message whose part directory is being read across passes, with its held iterator.
    part_scan: Option<PartScan>,
    /// Terminal unchanged-proof progress: the last completed database proven unchanged, so a
    /// generation with more databases than one pass can stat still completes. Reset whenever a
    /// database is read, because earlier pages would no longer describe the staged state.
    terminal_cursor: Option<PathBuf>,
    /// The last pass observed its cancel flag at a budget poll.
    cancelled: bool,
}

/// One message's part directory, read incrementally: the held iterator, the step-finish parts
/// decoded so far and the stamps they were read under. It survives pass boundaries (bounded by
/// the held-iterator ceiling) and is rebuilt from the start after a restart.
struct PartScan {
    message: PathBuf,
    message_stamp: FileStamp,
    directory: PathBuf,
    directory_stamp: FileStamp,
    entries: Option<DirEntries>,
    /// The entry whose processing ran out of budget; replayed first, never re-yielded.
    deferred: Option<PathBuf>,
    parts: Vec<StepFinishPart>,
    files: Vec<SpoolFile>,
    stamps: Vec<(PathBuf, FileStamp)>,
    failure: Option<FailureCode>,
    incomplete: bool,
    /// Entries of the final revalidation list (message, every part, directory) already proven
    /// unchanged. Revalidation resumes here after the budget ends, so a group with more parts
    /// than one pass can stat is still finished and never restarted.
    revalidated: usize,
}

pub(crate) fn unauthorized(authorization: SourceAuthorization) -> Option<PassReport> {
    let failure = if !authorization.selected {
        FailureCode::Unselected
    } else if authorization.consent != ConsentState::Enabled {
        FailureCode::Denied
    } else {
        return None;
    };
    Some(pass_report(
        PassOutcome::Unavailable,
        Some(failure),
        PassCounters::default(),
        0,
        None,
    ))
}

enum Flow {
    Continue,
    Stop,
}

impl<F: SourceFs> OpenCodeSource<F> {
    /// A runtime for one registered root. The caller has validated the roots, proved both
    /// identities and registered the source; everything else is loaded from `store` by `reload`.
    #[expect(
        clippy::too_many_arguments,
        reason = "one call site per attach path; each argument is a fact the caller already proved"
    )]
    fn new(
        fs: F,
        source_root: &Path,
        data_dir: &Path,
        home: &Path,
        roots: CanonicalRoots,
        source_identity: RootIdentity,
        data_identity: RootIdentity,
        source_id: String,
    ) -> Self {
        Self {
            fs,
            source_request: source_root.to_path_buf(),
            data_request: data_dir.to_path_buf(),
            home: home.to_path_buf(),
            frontier: DirectoryFrontier::new(&roots.source, Vec::new(), Vec::new()),
            roots,
            source_identity,
            data_identity,
            source_id,
            generation: 0,
            failures: BTreeMap::new(),
            needs_reload: true,
            needs_reset: false,
            part_scan: None,
            terminal_cursor: None,
            cancelled: false,
        }
    }

    /// One pass that stops like a budget stop when `cancel` is observed: groups completed before
    /// the poll publish through the unchanged stage/publish transactions, no group is split, and
    /// the pass reports [`PassCancelled`].
    fn pass_until(
        &mut self,
        store: &mut Store,
        authorization: SourceAuthorization,
        now_ms: i64,
        cancel: &AtomicBool,
    ) -> Result<PassReport, PassCancelled> {
        self.cancelled = false;
        let report = self.pass(store, authorization, now_ms, cancel);
        if std::mem::take(&mut self.cancelled) {
            Err(PassCancelled(report))
        } else {
            Ok(report)
        }
    }

    fn pass(
        &mut self,
        store: &mut Store,
        authorization: SourceAuthorization,
        now_ms: i64,
        cancel: &AtomicBool,
    ) -> PassReport {
        if let Some(report) = unauthorized(authorization) {
            return report;
        }
        if self.needs_reset {
            match store.reset_acquisition(&self.source_id, self.generation) {
                Ok(()) | Err(StoreError::StaleGeneration) => self.needs_reset = false,
                Err(error) => {
                    return self.report(
                        store,
                        PassOutcome::Partial,
                        Some(store_failure(error)),
                        PassCounters::default(),
                        0,
                    );
                }
            }
            self.needs_reload = true;
        }
        if self.needs_reload
            && let Err(error) = self.reload(store)
        {
            return self.report(
                store,
                PassOutcome::Partial,
                Some(store_failure(error)),
                PassCounters::default(),
                0,
            );
        }
        match store.retry_state(&self.source_id) {
            Ok(retry) => {
                if retry.next_retry_ms.is_some_and(|next| now_ms < next) {
                    // Backing off after a source change, idle or busy refusal: no source I/O
                    // until the deadline.
                    let reason = retry.reason.unwrap_or(FailureCode::SourceChanging);
                    return self.report(
                        store,
                        retry_outcome(reason, retry.change_count),
                        Some(reason),
                        PassCounters::default(),
                        0,
                    );
                }
            }
            Err(error) => {
                return self.report(
                    store,
                    PassOutcome::Partial,
                    Some(store_failure(error)),
                    PassCounters::default(),
                    0,
                );
            }
        }
        let mut state = PassState {
            cancel: Some(cancel),
            ..PassState::default()
        };
        match self.check_roots(&mut state.counters) {
            RootCheck::Valid => {}
            RootCheck::Budget => {
                return self.report(
                    store,
                    PassOutcome::CatchingUp,
                    Some(FailureCode::LimitExceeded),
                    state.counters,
                    0,
                );
            }
            RootCheck::Conflict => {
                return self.report(
                    store,
                    PassOutcome::Unavailable,
                    Some(FailureCode::RootOverlap),
                    state.counters,
                    0,
                );
            }
        }
        if self.frontier.restart_blocked {
            return self.report_restart_blocked(store, state.counters, now_ms);
        }
        self.frontier.begin_pass();
        state.source_seen =
            match store.generation_has_source_files(&self.source_id, self.generation) {
                Ok(seen) => seen,
                Err(error) => {
                    return self.report(
                        store,
                        PassOutcome::Partial,
                        Some(store_failure(error)),
                        state.counters,
                        0,
                    );
                }
            };
        self.resume_part_scan(store, &mut state);
        // Every directory of this generation has been listed and each message in them read, so
        // another refresh of the known messages could only start one more held scan and postpone
        // finalization forever; what is unfinished (held scan, failures, databases) still resumes.
        let drained = self.frontier.is_drained();
        self.current_lane(store, &mut state, drained);
        if !state.changing && !state.caught_up {
            self.walk(store, &mut state);
        }
        self.cancelled = state.cancelled;
        self.finish(store, state, now_ms)
    }

    /// Reserved lane: persisted failed and known source paths are revalidated before general
    /// discovery, so a current mutable record is read even when it sits behind a huge backlog.
    fn current_lane(&mut self, store: &mut Store, state: &mut PassState, drained: bool) {
        let mut relatives: Vec<PathBuf> = self.failures.keys().cloned().collect();
        match store.known_paths(&self.source_id, MAX_KNOWN_PATHS_PER_PASS) {
            Ok(known) => relatives.extend(
                known
                    .into_iter()
                    .filter(|path| !drained || path.parser_kind != "opencode_json_message")
                    .map(|path| path.relative_path),
            ),
            Err(_) => state.skip(FailureCode::Store),
        }
        let mut seen = HashSet::new();
        for relative in relatives {
            if !seen.insert(relative.clone()) {
                continue;
            }
            if Lane::Current.exhausted(&state.counters)
                || state.changing
                || state.caught_up
                || state.cancel_requested()
            {
                break;
            }
            let path = self.roots.source.join(&relative);
            if state.visited.contains(&path) {
                continue;
            }
            let metadata = match stat_optional(&self.fs, &path, &mut state.counters) {
                Ok(Some(metadata)) => metadata,
                Ok(None) => {
                    if self.failures.contains_key(&relative) {
                        state.recovered.push(relative);
                    }
                    continue;
                }
                Err(Stop::Budget | Stop::ValidationBudget) => break,
                Err(Stop::Fail(code)) => {
                    state.skip(code);
                    continue;
                }
            };
            if metadata.file_type().is_symlink() {
                state.skip(FailureCode::RootOverlap);
                continue;
            }
            if !metadata.is_file() {
                continue;
            }
            state.revalidated.push(relative.clone());
            let outcome = self.process_file(store, &path, &metadata, state, Lane::Current);
            // The reserved lane running out of budget ends only itself; discovery still runs.
            if matches!(outcome, FileOutcome::Budget) {
                state.current_incomplete = true;
                break;
            }
            if let Flow::Stop = self.apply(&path, outcome, state, None) {
                break;
            }
        }
    }

    /// The message whose part directory is held open is finished first, with the reserved lane's
    /// half of the budget, so every pass advances it and no other message can take its slot.
    fn resume_part_scan(&mut self, store: &mut Store, state: &mut PassState) {
        let Some(scan) = &self.part_scan else {
            return;
        };
        let path = scan.message.clone();
        let metadata = match stat_optional(&self.fs, &path, &mut state.counters) {
            Ok(Some(metadata)) if metadata.is_file() => metadata,
            Ok(_) => {
                self.part_scan = None;
                return;
            }
            Err(Stop::Budget | Stop::ValidationBudget) => return,
            Err(Stop::Fail(code)) => {
                self.part_scan = None;
                state.skip(code);
                return;
            }
        };
        let outcome = self.process_file(store, &path, &metadata, state, Lane::Current);
        if matches!(outcome, FileOutcome::Budget) {
            return;
        }
        let _ = self.apply(&path, outcome, state, None);
    }

    /// Historical lane: bounded round-robin traversal of the directory frontier.
    fn walk(&mut self, store: &mut Store, state: &mut PassState) {
        loop {
            if Lane::Full.exhausted(&state.counters) || state.cancel_requested() {
                state.caught_up = true;
                break;
            }
            let held = self.part_scan.as_ref().map(|scan| scan.message.as_path());
            let step = self.frontier.next(
                &self.fs,
                &self.roots,
                self.source_identity,
                held,
                &mut state.counters,
            );
            match step {
                WalkStep::Exhausted => break,
                WalkStep::Capped => {
                    state.caught_up = true;
                    break;
                }
                WalkStep::Error(code) => state.skip(code),
                WalkStep::CompletedDirectory(stat) => state.files.push(stat),
                WalkStep::Entry(entry) => {
                    if let Flow::Stop = self.visit(store, entry, state) {
                        break;
                    }
                }
            }
        }
    }

    fn visit(&mut self, store: &mut Store, entry: Entry, state: &mut PassState) -> Flow {
        if entry.path.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES {
            state.skip(FailureCode::LimitExceeded);
            return Flow::Continue;
        }
        let metadata = match source_metadata(&self.fs, &entry.path, &mut state.counters) {
            Ok(metadata) => metadata,
            Err(Stop::Budget | Stop::ValidationBudget) => {
                state.caught_up = true;
                self.frontier.defer(entry);
                return Flow::Stop;
            }
            Err(Stop::Fail(code)) => {
                state.skip(code);
                return Flow::Continue;
            }
        };
        if metadata.file_type().is_symlink() {
            state.skip(FailureCode::RootOverlap);
            return Flow::Continue;
        }
        if metadata.is_dir() {
            self.visit_directory(entry, &metadata, state);
            return Flow::Continue;
        }
        if !metadata.is_file() {
            return Flow::Continue;
        }
        let path = entry.path.clone();
        let outcome = self.process_file(store, &path, &metadata, state, Lane::Full);
        self.apply(&path, outcome, state, Some(entry))
    }

    fn visit_directory(
        &mut self,
        entry: Entry,
        metadata: &std::fs::Metadata,
        state: &mut PassState,
    ) {
        let Ok(relative) = entry.path.strip_prefix(&self.roots.source) else {
            state.skip(FailureCode::RootOverlap);
            return;
        };
        if is_part_tree(relative) {
            self.frontier.mark_complete(entry.path.clone());
            if let Ok(stat) = spool_file(&self.roots, &entry.path, metadata, "directory") {
                state.files.push(stat);
            }
            return;
        }
        if entry.depth >= MAX_DIRECTORY_DEPTH {
            state.skip(FailureCode::LimitExceeded);
            return;
        }
        let stat = match spool_file(&self.roots, &entry.path, metadata, "directory") {
            Ok(stat) => stat,
            Err(code) => {
                state.skip(code);
                return;
            }
        };
        if entry.path.to_str().is_none() {
            state.skip(FailureCode::InvalidRecord);
            return;
        }
        if !self.frontier.enqueue(DirectoryWork {
            path: entry.path,
            depth: entry.depth + 1,
            stat: Some(stat),
            restart_blocked: false,
        }) {
            self.frontier.requeue_source();
            state.skip(FailureCode::LimitExceeded);
        }
    }

    /// Folds one file result into the pass. `entry` is the traversal entry to replay next pass
    /// when the file could not be finished within budget.
    fn apply(
        &mut self,
        path: &Path,
        outcome: FileOutcome,
        state: &mut PassState,
        entry: Option<Entry>,
    ) -> Flow {
        let relative = path
            .strip_prefix(&self.roots.source)
            .map(Path::to_path_buf)
            .ok();
        match outcome {
            FileOutcome::Done { rejected, more } => {
                state.source_seen = true;
                if let Some(code) = rejected {
                    state.reject(code);
                }
                if let Some(relative) = relative
                    && self.failures.contains_key(&relative)
                {
                    state.recovered.push(relative);
                }
                if more {
                    if let Some(entry) = entry {
                        state.caught_up = true;
                        self.frontier.defer(entry);
                    } else {
                        state.current_incomplete = true;
                    }
                    return Flow::Stop;
                }
                Flow::Continue
            }
            FileOutcome::Failed(code) => {
                if let Some(relative) = relative {
                    state.pending.push(PendingMark {
                        relative_path: relative.clone(),
                        reason: code,
                    });
                    state.failed.push(FileFailure {
                        relative_path: relative,
                        code,
                    });
                } else {
                    state.skip(code);
                }
                Flow::Continue
            }
            FileOutcome::Changing => {
                state.changing = true;
                state.changing_path = relative;
                Flow::Stop
            }
            FileOutcome::Budget => {
                if let Some(entry) = entry {
                    state.caught_up = true;
                    self.frontier.defer(entry);
                } else {
                    state.current_incomplete = true;
                }
                Flow::Stop
            }
            FileOutcome::Skipped => Flow::Continue,
        }
    }

    fn process_file(
        &mut self,
        store: &mut Store,
        path: &Path,
        metadata: &std::fs::Metadata,
        state: &mut PassState,
        lane: Lane,
    ) -> FileOutcome {
        if !state.visited.insert(path.to_path_buf()) {
            return FileOutcome::Skipped;
        }
        if is_opencode_database(path) {
            self.process_database(store, path, metadata, state, lane)
        } else if let Some((session_id, message_id)) = message_path(&self.roots.source, path) {
            self.process_json_message(&session_id, &message_id, path, metadata, state, lane)
        } else {
            FileOutcome::Skipped
        }
    }

    fn check_file_roots(&mut self, state: &mut PassState) -> Result<(), FileOutcome> {
        match self.check_roots(&mut state.counters) {
            RootCheck::Valid => {
                state.verified_files = state.files.len();
                Ok(())
            }
            RootCheck::Budget => {
                self.frontier.validation_budget = true;
                Err(FileOutcome::Budget)
            }
            RootCheck::Conflict => Err(FileOutcome::Failed(FailureCode::RootOverlap)),
        }
    }

    fn finish(&mut self, store: &mut Store, mut state: PassState, now_ms: i64) -> PassReport {
        if state.changing {
            let paths: Vec<PathBuf> = state.changing_path.iter().cloned().collect();
            return self.changed(store, state.counters, now_ms, &paths, &[]);
        }
        // A parked directory is complete once its scan is no longer held.
        self.frontier
            .release_parked(self.part_scan.as_ref().map(|scan| scan.message.as_path()));
        // Work that outlives the pass (a held part scan, an unfinished current-lane file) keeps
        // the generation open: the pass is catching up, never idle, consistent or terminal.
        if state.current_incomplete || self.part_scan.is_some() {
            state.caught_up = true;
        }
        if self.frontier.is_drained() && !state.caught_up {
            for (path, expected) in [
                (&self.roots.source, self.source_identity),
                (&self.roots.data, self.data_identity),
            ] {
                match root_identity(&self.fs, path, &mut state.counters) {
                    Ok(identity) if identity == expected => {}
                    Err(Stop::Budget | Stop::ValidationBudget) => {
                        self.frontier.validation_budget = true;
                        self.frontier.validation_retry = true;
                        state.caught_up = true;
                    }
                    _ => {
                        state.skip(FailureCode::RootOverlap);
                        state.caught_up = true;
                    }
                }
                if state.caught_up {
                    break;
                }
            }
        }
        let mut prospective = self.failures.clone();
        for failed in &state.failed {
            prospective.insert(failed.relative_path.clone(), failed.code);
        }
        for recovered in &state.recovered {
            prospective.remove(recovered);
        }
        let (mut database_failure, mut other_failure) = (None, None);
        for (path, code) in &prospective {
            if is_database_name(path) {
                database_failure = lesser(database_failure, *code);
            } else {
                other_failure = lesser(other_failure, *code);
            }
        }
        let mut failure = state
            .skipped
            .filter(|code| *code == FailureCode::RootOverlap)
            .or(database_failure)
            .or(other_failure)
            .or(state.rejection)
            .or(state.skipped);
        let root_complete = self.frontier.is_drained() && !state.caught_up;
        // Any database failure is unavailable whatever else was read, so the classification
        // never depends on which sibling happened to be visited first.
        let outcome = if database_failure.is_some() {
            PassOutcome::Unavailable
        } else if failure == Some(FailureCode::RootOverlap) {
            PassOutcome::Partial
        } else if state.caught_up {
            PassOutcome::CatchingUp
        } else if failure.is_some() {
            PassOutcome::Partial
        } else if !state.source_seen {
            PassOutcome::Unavailable
        } else {
            PassOutcome::Consistent
        };
        if outcome == PassOutcome::Unavailable && failure.is_none() {
            failure = Some(FailureCode::SourceIdle);
        }
        if outcome == PassOutcome::Unavailable {
            return self.finish_unavailable(
                store,
                state,
                prospective,
                database_failure,
                failure,
                now_ms,
            );
        }
        if root_complete && !state.source_seen {
            // Nothing readable was found: walk the tree again next pass instead of finalizing an
            // empty generation.
            self.frontier = DirectoryFrontier::new(
                &self.roots.source,
                vec![(self.roots.source.clone(), 0, false)],
                Vec::new(),
            );
        }
        let conflicts = candidate_keys(&self.roots.source, &state.candidates);
        if root_complete && state.source_seen {
            match self.completed_databases_unchanged(store, &mut state) {
                Ok(true) => {}
                Ok(false) => return self.changed(store, state.counters, now_ms, &[], &conflicts),
                Err(Stop::Budget | Stop::ValidationBudget) => {
                    // Not enough budget left to prove the staged databases unchanged: stay
                    // catching up and prove it with a fresh budget next pass.
                    self.frontier.validation_budget = true;
                    state.caught_up = true;
                }
                Err(Stop::Fail(code)) => {
                    return self.report(store, PassOutcome::Partial, Some(code), state.counters, 0);
                }
            }
        }
        let root_complete = root_complete && !state.caught_up;
        let outcome = if state.caught_up && outcome == PassOutcome::Consistent {
            PassOutcome::CatchingUp
        } else {
            outcome
        };
        let unverified = &state.files[state.verified_files..];
        let retry_files = (self.frontier.validation_budget
            && (self.frontier.validation_retry
                || unverified
                    .iter()
                    .any(|file| file.parser_kind == "directory")))
        .then_some(unverified);
        if let Some(files) = retry_files {
            self.frontier.retry_unverified_directories(files);
        }
        let frontier = self.frontier.snapshot();
        let batch = StageBatch {
            visited: &state.revalidated,
            candidates: &state.candidates,
            files: &state.files,
            progress: &state.progress,
            failed: &state.failed,
            recovered: &state.recovered,
            pending: &state.pending,
        };
        if root_complete && state.source_seen {
            let mut staged = match store.load_staged_candidates(
                &self.source_id,
                &self.roots.source,
                self.generation,
            ) {
                Ok(staged) => staged,
                Err(error) => return self.store_failed(store, error, state.counters),
            };
            staged.extend(state.candidates.iter().cloned());
            if let Err(ResolveError::SourceChanging) = opencode::resolve_candidates(staged) {
                return self.changed(store, state.counters, now_ms, &[], &conflicts);
            }
            let terminal = failure.is_none() && !state.incomplete;
            let result = store.commit_generation(CommitRequest {
                source_id: &self.source_id,
                root: &self.roots.source,
                generation: self.generation,
                batch,
                outcome,
                failure,
                rejection: state.rejection,
                terminal,
                counters: state.counters,
                now_ms,
            });
            return match result {
                Ok(summary) => {
                    self.generation = self.generation.saturating_add(1);
                    self.failures = prospective;
                    self.frontier =
                        DirectoryFrontier::new(&self.roots.source, Vec::new(), Vec::new());
                    self.part_scan = None;
                    self.report(
                        store,
                        summary.outcome,
                        summary.failure,
                        state.counters,
                        summary.records_committed,
                    )
                }
                Err(StoreError::StageConflict) => {
                    self.changed(store, state.counters, now_ms, &[], &conflicts)
                }
                Err(error) => {
                    // A failed finalization invalidates the acquisition it would have published:
                    // drop the staged evidence so every source is read again before trusting it.
                    self.invalidate_acquisition(store);
                    self.store_failed(store, error, state.counters)
                }
            };
        }
        let result = store.stage_scan_with_freshness(
            StageRequest {
                source_id: &self.source_id,
                root: &self.roots.source,
                generation: self.generation,
                batch,
                frontier: Some(&frontier),
                outcome,
                failure,
                rejection: state.rejection,
                backoff: None,
                stable_read: state.stable_read,
                counters: state.counters,
                now_ms,
            },
            !self.frontier.validation_budget,
            retry_files,
        );
        match result {
            Ok(summary) => {
                self.failures = prospective;
                if failure == Some(FailureCode::RootOverlap) && self.reload(store).is_err() {
                    self.needs_reload = true;
                }
                self.report(
                    store,
                    outcome,
                    failure,
                    state.counters,
                    summary.records_committed,
                )
            }
            Err(StoreError::StageConflict) => {
                self.changed(store, state.counters, now_ms, &[], &conflicts)
            }
            Err(error) => self.store_failed(store, error, state.counters),
        }
    }

    /// An unavailable pass publishes nothing and advances nothing: only the failure bookkeeping
    /// (and a durable idle/busy retry) is recorded. The in-memory traversal that ran ahead of
    /// the store is rebuilt from what is durable.
    fn finish_unavailable(
        &mut self,
        store: &mut Store,
        state: PassState,
        prospective: BTreeMap<PathBuf, FailureCode>,
        database_failure: Option<FailureCode>,
        failure: Option<FailureCode>,
        now_ms: i64,
    ) -> PassReport {
        let backoff = database_failure
            .filter(|code| matches!(code, FailureCode::SourceIdle | FailureCode::Busy));
        let result = store.stage_scan(StageRequest {
            source_id: &self.source_id,
            root: &self.roots.source,
            generation: self.generation,
            batch: StageBatch {
                failed: &state.failed,
                recovered: &state.recovered,
                pending: &state.pending,
                ..StageBatch::default()
            },
            frontier: None,
            outcome: PassOutcome::Unavailable,
            failure,
            rejection: None,
            backoff,
            stable_read: false,
            counters: state.counters,
            now_ms,
        });
        self.part_scan = None;
        match result {
            Ok(_) => {
                self.failures = prospective;
                if self.reload(store).is_err() {
                    self.needs_reload = true;
                }
                self.report(store, PassOutcome::Unavailable, failure, state.counters, 0)
            }
            Err(error) => self.store_failed(store, error, state.counters),
        }
    }

    /// Terminal proof that no database read earlier in this generation changed since: its
    /// identity set (and, without a write-ahead log, its main-file stamp) must still be the one
    /// it was read under. Databases not in `source_files` yet are covered.
    fn completed_databases_unchanged(
        &mut self,
        store: &mut Store,
        state: &mut PassState,
    ) -> Result<bool, Stop> {
        // A database read in this pass may differ from what earlier pages proved: start over.
        if state.database_opens > 0 {
            self.terminal_cursor = None;
        }
        loop {
            let page = store
                .completed_databases(
                    &self.source_id,
                    self.generation,
                    self.terminal_cursor.as_deref(),
                )
                .map_err(|error| Stop::Fail(store_failure(error)))?;
            let Some(last) = page.last().map(|database| database.relative_path.clone()) else {
                self.terminal_cursor = None;
                return Ok(true);
            };
            for database in page {
                let path = self.roots.source.join(&database.relative_path);
                if !state
                    .progress
                    .iter()
                    .any(|update| update.relative_path == database.relative_path)
                    && !self.database_unchanged(&path, &database, state)?
                {
                    self.terminal_cursor = None;
                    return Ok(false);
                }
                // Resume after this database if the budget ends before the next one is proven.
                self.terminal_cursor = Some(database.relative_path);
            }
            self.terminal_cursor = Some(last);
        }
    }

    fn database_unchanged(
        &self,
        path: &Path,
        database: &crate::store::CompletedDatabase,
        state: &mut PassState,
    ) -> Result<bool, Stop> {
        let (identity, stamp) = sqlite_ro::current_state(&self.fs, path, &mut state.counters)
            .map_err(|code| {
                if code == FailureCode::LimitExceeded {
                    Stop::Budget
                } else {
                    Stop::Fail(code)
                }
            })?;
        if identity.key() != database.identity {
            return Ok(false);
        }
        // Without a write-ahead log the main-file stamp is the whole witness.
        let stamp_matches = identity.wal.exists
            || stamp.is_some_and(|stamp| {
                (stamp.device, stamp.inode, stamp.size, stamp.mtime_ns)
                    == (
                        database.device,
                        database.inode,
                        database.size,
                        database.mtime_ns,
                    )
            });
        Ok(stamp_matches)
    }

    /// Drops the staged acquisition of this generation (published history stays). When the store
    /// cannot take the write, the reset is retried before the next pass.
    fn invalidate_acquisition(&mut self, store: &mut Store) {
        self.part_scan = None;
        match store.reset_acquisition(&self.source_id, self.generation) {
            Ok(()) | Err(StoreError::StaleGeneration) => {}
            Err(_) => self.needs_reset = true,
        }
    }

    /// Source identity changed under an acquisition: drop acquisition-local state, keep the
    /// committed baseline flagged pending (restoring groups a competing acquisition touched), and
    /// back off before touching the source again.
    fn changed(
        &mut self,
        store: &mut Store,
        counters: PassCounters,
        now_ms: i64,
        paths: &[PathBuf],
        conflicts: &[(PathBuf, String, u8)],
    ) -> PassReport {
        self.part_scan = None;
        let result = store.discard_generation(DiscardRequest {
            source_id: &self.source_id,
            generation: self.generation,
            paths,
            conflicts,
            failure: FailureCode::SourceChanging,
            counters,
            now_ms,
        });
        match result {
            Ok(summary) => {
                if self.reload(store).is_err() {
                    self.needs_reload = true;
                }
                self.report(
                    store,
                    summary.outcome,
                    Some(FailureCode::SourceChanging),
                    counters,
                    0,
                )
            }
            Err(error) => self.store_failed(store, error, counters),
        }
    }

    /// A store write failed. Whatever it left durable is the truth: reload from it rather than
    /// continuing from in-memory state that may be ahead of, or behind, what was committed.
    fn store_failed(
        &mut self,
        store: &mut Store,
        error: StoreError,
        counters: PassCounters,
    ) -> PassReport {
        if self.reload(store).is_err() {
            self.needs_reload = true;
        }
        // Storage decoding, numeric-range and SQL failures leave history untouched but make the
        // source unavailable; only commit/staging policy failures stay partial.
        let outcome = match error {
            StoreError::InvalidStoredValue | StoreError::CountOutOfRange | StoreError::Sqlite => {
                PassOutcome::Unavailable
            }
            _ => PassOutcome::Partial,
        };
        self.report(store, outcome, Some(store_failure(error)), counters, 0)
    }

    /// Rebuilds all acquisition-local state from the store: generation, frontier, completed
    /// directories and unresolved file failures.
    fn reload(&mut self, store: &mut Store) -> Result<(), StoreError> {
        self.needs_reload = true;
        let generation = store.generation(&self.source_id)?;
        let pending = store.load_frontier(&self.source_id, &self.roots.source, generation)?;
        let completed =
            store.load_completed_directories(&self.source_id, &self.roots.source, generation)?;
        let failures = store
            .load_failures(&self.source_id)?
            .into_iter()
            .map(|failure| (failure.relative_path, failure.code))
            .collect();
        self.generation = generation;
        self.failures = failures;
        self.frontier = DirectoryFrontier::new(&self.roots.source, pending, completed);
        self.part_scan = None;
        self.terminal_cursor = None;
        self.needs_reload = false;
        Ok(())
    }

    fn check_roots(&self, counters: &mut PassCounters) -> RootCheck {
        match discovery::validate_roots(
            &self.fs,
            &self.source_request,
            &self.data_request,
            &self.home,
            counters,
        ) {
            Ok(roots) if roots == self.roots => {}
            Err(RootError::LimitExceeded) => return RootCheck::Budget,
            _ => return RootCheck::Conflict,
        }
        self.check_identities(counters)
    }

    fn check_identities(&self, counters: &mut PassCounters) -> RootCheck {
        for (path, expected) in [
            (&self.roots.source, self.source_identity),
            (&self.roots.data, self.data_identity),
        ] {
            match root_identity(&self.fs, path, counters) {
                Ok(identity) if identity == expected => {}
                Err(Stop::Budget | Stop::ValidationBudget) => return RootCheck::Budget,
                _ => return RootCheck::Conflict,
            }
        }
        RootCheck::Valid
    }

    fn report_restart_blocked(
        &mut self,
        store: &mut Store,
        counters: PassCounters,
        now_ms: i64,
    ) -> PassReport {
        let mut completed = match store.load_completed_directories(
            &self.source_id,
            &self.roots.source,
            self.generation,
        ) {
            Ok(completed) => completed,
            Err(error) => {
                return self.report(
                    store,
                    PassOutcome::Partial,
                    Some(store_failure(error)),
                    counters,
                    0,
                );
            }
        };
        completed.retain(|path| path != &self.roots.source);
        // Every directory that was still being read is listed again from its beginning (an
        // iterator position is never persisted); the completed ones stay completed.
        let mut incomplete =
            match store.load_frontier(&self.source_id, &self.roots.source, self.generation) {
                Ok(frontier) => frontier,
                Err(error) => {
                    return self.report(
                        store,
                        PassOutcome::Partial,
                        Some(store_failure(error)),
                        counters,
                        0,
                    );
                }
            };
        for entry in &mut incomplete {
            entry.2 = false;
        }
        if incomplete.is_empty() {
            incomplete.push((self.roots.source.clone(), 0, false));
        }
        self.frontier = DirectoryFrontier::new(&self.roots.source, incomplete, completed);
        let frontier = self.frontier.snapshot();
        let result = store.stage_scan(StageRequest {
            source_id: &self.source_id,
            root: &self.roots.source,
            generation: self.generation,
            batch: StageBatch::default(),
            frontier: Some(&frontier),
            outcome: PassOutcome::Partial,
            failure: Some(FailureCode::LimitExceeded),
            rejection: None,
            backoff: None,
            stable_read: false,
            counters,
            now_ms,
        });
        match result {
            Ok(_) => self.report(
                store,
                PassOutcome::Partial,
                Some(FailureCode::LimitExceeded),
                counters,
                0,
            ),
            Err(error) => self.store_failed(store, error, counters),
        }
    }

    fn report(
        &self,
        store: &Store,
        outcome: PassOutcome,
        failure: Option<FailureCode>,
        counters: PassCounters,
        records: u32,
    ) -> PassReport {
        let last_good_ms = store.last_success_ms(&self.source_id).ok().flatten();
        pass_report(outcome, failure, counters, records, last_good_ms)
    }
}

fn stop_outcome(stop: Stop) -> FileOutcome {
    match stop {
        Stop::Budget | Stop::ValidationBudget => FileOutcome::Budget,
        Stop::Fail(code) => FileOutcome::Failed(code),
    }
}

impl<F: SourceFs> OpenCodeSource<F> {
    fn process_database(
        &mut self,
        store: &mut Store,
        path: &Path,
        initial: &std::fs::Metadata,
        state: &mut PassState,
        lane: Lane,
    ) -> FileOutcome {
        if state.database_opens >= MAX_SOURCE_DATABASES_PER_PASS {
            return FileOutcome::Budget;
        }
        let canonical = match canonical_source_file(
            &self.fs,
            &self.roots.source,
            path,
            initial,
            &mut state.counters,
        ) {
            Ok(path) => path,
            Err(stop) => return stop_outcome(stop),
        };
        if let Err(outcome) = self.check_file_roots(state) {
            return outcome;
        }
        let stat =
            match source_metadata(&self.fs, &canonical, &mut state.counters).and_then(|metadata| {
                spool_file(&self.roots, &canonical, &metadata, "sqlite").map_err(Stop::Fail)
            }) {
                Ok(stat) => stat,
                Err(stop) => return stop_outcome(stop),
            };
        let before = match sqlite_ro::preflight(&self.fs, &canonical, &mut state.counters) {
            Ok(identity) => identity,
            Err(FailureCode::LimitExceeded) => {
                self.frontier.validation_budget = true;
                return FileOutcome::Budget;
            }
            Err(code) => return FileOutcome::Failed(code),
        };
        let Ok(relative) = canonical.strip_prefix(&self.roots.source) else {
            return FileOutcome::Failed(FailureCode::RootOverlap);
        };
        let relative = relative.to_path_buf();
        // A saved cursor and its staged candidates belong to the database and sidecar set they
        // were read under; any other set means the source changed under the sweep.
        let identity = before.key();
        let cursor = match store.saved_progress(&self.source_id, &relative, self.generation) {
            Ok(Some(saved)) if saved.identity.as_deref() == Some(identity.as_str()) => saved.cursor,
            Ok(Some(_)) => return FileOutcome::Changing,
            Ok(None) => None,
            Err(error) => return FileOutcome::Failed(store_failure(error)),
        };
        if opencode::cursor_is_complete(cursor.as_deref()).unwrap_or(false) {
            state.files.push(stat);
            return FileOutcome::Done {
                rejected: None,
                more: false,
            };
        }
        // Every metadata-class operation the read-only VFS and its pinned parent perform for
        // this read is charged physically, before it runs, against what the pass still has; four
        // are kept back for the identity proof that follows the read.
        let allowance = MAX_METADATA_CALLS
            .saturating_sub(state.counters.stat_calls)
            .saturating_sub(IDENTITY_PROOF_STATS);
        if allowance == 0 {
            self.frontier.validation_budget = true;
            return FileOutcome::Budget;
        }
        state.counters.source_opens = state.counters.source_opens.saturating_add(1);
        state.database_opens += 1;
        let meter = sqlite_ro::MetadataMeter::begin(allowance);
        let cancel = state.cancel;
        let read = match self.fs.open_sqlite(&canonical) {
            Ok(mut connection) => opencode::read_sqlite(
                &mut connection,
                &canonical,
                cursor.as_deref(),
                &mut state.counters,
                ReadBudget {
                    rows: lane.rows(),
                    bytes: lane.bytes(),
                },
                cancel,
            ),
            Err(error) => Err(sqlite_open_failure(error)),
        };
        // A flag the sweep stopped on is recorded, so the pass reports the cancel.
        state.cancel_requested();
        let (used, refused) = meter.state();
        drop(meter);
        state.counters.stat_calls = state.counters.stat_calls.saturating_add(used);
        if refused {
            // A physical operation was refused for lack of allowance: the read is discarded and
            // retried whole with a fresh budget.
            self.frontier.validation_budget = true;
            return FileOutcome::Budget;
        }
        let batch = match read {
            Ok(batch) => batch,
            Err(code) => {
                if let Err(outcome) = self.check_file_roots(state) {
                    return outcome;
                }
                return FileOutcome::Failed(code);
            }
        };
        match sqlite_ro::identity_unchanged(&self.fs, &canonical, before, &mut state.counters) {
            Ok(true) => {}
            Ok(false) => return FileOutcome::Changing,
            Err(FailureCode::LimitExceeded) => {
                self.frontier.validation_budget = true;
                return FileOutcome::Budget;
            }
            Err(code) => return FileOutcome::Failed(code),
        }
        if let Err(outcome) = self.check_file_roots(state) {
            return outcome;
        }
        state.candidates.extend(batch.records);
        state.progress.push(ProgressUpdate {
            relative_path: relative,
            next_cursor: batch.cursor_key,
            identity,
        });
        state.files.push(stat);
        state.stable_read = true;
        FileOutcome::Done {
            rejected: batch.failure,
            more: !batch.complete_sweep,
        }
    }

    fn process_json_message(
        &mut self,
        session_id: &str,
        message_id: &str,
        path: &Path,
        initial: &std::fs::Metadata,
        state: &mut PassState,
        lane: Lane,
    ) -> FileOutcome {
        let canonical = match canonical_source_file(
            &self.fs,
            &self.roots.source,
            path,
            initial,
            &mut state.counters,
        ) {
            Ok(path) => path,
            Err(stop) => return stop_outcome(stop),
        };
        let message_stat = match source_metadata(&self.fs, &canonical, &mut state.counters) {
            Ok(metadata) => metadata,
            Err(stop) => return stop_outcome(stop),
        };
        let message_spool = match spool_file(
            &self.roots,
            &canonical,
            &message_stat,
            "opencode_json_message",
        ) {
            Ok(spool) => spool,
            Err(code) => return FileOutcome::Failed(code),
        };
        let stamp = FileStamp::of(&message_stat);
        if message_stat.len() > MAX_OPENCODE_RECORD_BYTES as u64 {
            return self.reject_message(
                &canonical,
                message_spool,
                FailureCode::RecordTooLarge,
                state,
            );
        }
        if state.counters.bytes_read.saturating_add(message_stat.len()) > lane.bytes()
            || state.counters.rows_read >= lane.rows()
        {
            return FileOutcome::Budget;
        }
        if let Err(outcome) = self.check_file_roots(state) {
            return outcome;
        }
        state.counters.source_opens = state.counters.source_opens.saturating_add(1);
        let read = match self.fs.read_bounded(
            &canonical,
            read_allowance(lane, &state.counters),
            &mut state.counters,
        ) {
            Ok(read) => read,
            Err(error) => {
                if let Err(outcome) = self.check_file_roots(state) {
                    return outcome;
                }
                return stop_outcome(stop_of(error));
            }
        };
        state.counters.bytes_read = state
            .counters
            .bytes_read
            .saturating_add(read.bytes.len() as u64);
        state.counters.rows_read = state.counters.rows_read.saturating_add(1);
        match self.check_identities(&mut state.counters) {
            RootCheck::Valid => state.verified_files = state.files.len(),
            RootCheck::Budget => {
                self.frontier.validation_budget = true;
                return FileOutcome::Budget;
            }
            RootCheck::Conflict => return FileOutcome::Failed(FailureCode::RootOverlap),
        }
        if read.before != stamp || read.before != read.after {
            return FileOutcome::Failed(FailureCode::SourceChanging);
        }
        if read.bytes.len() > MAX_OPENCODE_RECORD_BYTES {
            return self.reject_message(
                &canonical,
                message_spool,
                FailureCode::RecordTooLarge,
                state,
            );
        }
        let mut scan = match self.part_scan.take() {
            Some(scan) if scan.message == canonical && scan.message_stamp == stamp => Some(scan),
            Some(occupant) => {
                if occupant.message == canonical {
                    // The message changed since its parts were read: start over.
                    None
                } else {
                    // The one held part iterator belongs to another message; it is finished first.
                    self.part_scan = Some(occupant);
                    return FileOutcome::Budget;
                }
            }
            None => None,
        };
        if scan.is_none() {
            let part_directory = self
                .roots
                .source
                .join("storage")
                .join("part")
                .join(message_id);
            scan = match self.begin_part_scan(&canonical, stamp, &part_directory, state, lane) {
                Ok(scan) => scan,
                Err(outcome) => return outcome,
            };
        }
        let mut scan = match scan {
            // No part directory: the message stands alone.
            None => PartScan::empty(canonical.clone(), stamp),
            Some(mut scan) => match self.advance_part_scan(&mut scan, state, lane) {
                ScanStep::Done => scan,
                ScanStep::Budget => {
                    self.part_scan = Some(scan);
                    return FileOutcome::Budget;
                }
                ScanStep::Failed(outcome) => return outcome,
            },
        };
        match self.revalidate(&canonical, stamp, &mut scan, state, lane) {
            Ok(true) => {}
            Ok(false) => return FileOutcome::Failed(FailureCode::SourceChanging),
            Err(Stop::Budget | Stop::ValidationBudget) => {
                self.part_scan = Some(scan);
                return FileOutcome::Budget;
            }
            Err(stop) => return stop_outcome(stop),
        }
        state.files.push(message_spool);
        state.files.extend(scan.files);
        if let Some(code) = scan.failure {
            // Retain the last complete group; the failure is visible and the group is pending.
            self.mark_pending(&canonical, code, state);
            return FileOutcome::Done {
                rejected: Some(code),
                more: false,
            };
        }
        state.stable_read = true;
        let mut rejected = None;
        match opencode::decode_json_group(
            session_id,
            message_id,
            &read.bytes,
            &scan.parts,
            scan.incomplete,
            &canonical,
        ) {
            Ok(Some(record)) => {
                if record.pending_partial {
                    state.counters.rejected_records =
                        state.counters.rejected_records.saturating_add(1);
                    rejected = Some(FailureCode::InvalidRecord);
                }
                state.candidates.push(record);
            }
            Ok(None) | Err(DecodeError::NotUsage) => {}
            Err(DecodeError::RecordTooLarge) => {
                state.counters.rejected_records = state.counters.rejected_records.saturating_add(1);
                rejected = Some(FailureCode::RecordTooLarge);
                self.mark_pending(&canonical, FailureCode::RecordTooLarge, state);
            }
            Err(DecodeError::InvalidRecord) => {
                state.counters.rejected_records = state.counters.rejected_records.saturating_add(1);
                rejected = Some(FailureCode::InvalidRecord);
                self.mark_pending(&canonical, FailureCode::InvalidRecord, state);
            }
        }
        FileOutcome::Done {
            rejected,
            more: false,
        }
    }

    /// An unusable JSON parent keeps the last complete group but marks it pending, with the exact
    /// reason, until a stable correction replaces it.
    fn mark_pending(&self, canonical: &Path, reason: FailureCode, state: &mut PassState) {
        if let Ok(relative) = canonical.strip_prefix(&self.roots.source) {
            state.pending.push(PendingMark {
                relative_path: relative.to_path_buf(),
                reason,
            });
        }
    }

    fn reject_message(
        &self,
        canonical: &Path,
        spool: SpoolFile,
        code: FailureCode,
        state: &mut PassState,
    ) -> FileOutcome {
        state.counters.rejected_records = state.counters.rejected_records.saturating_add(1);
        state.files.push(spool);
        self.mark_pending(canonical, code, state);
        FileOutcome::Done {
            rejected: Some(code),
            more: false,
        }
    }

    /// Opens a message's part directory and returns the scan that will read it; `None` when the
    /// message has no part directory.
    fn begin_part_scan(
        &mut self,
        message: &Path,
        message_stamp: FileStamp,
        directory: &Path,
        state: &mut PassState,
        lane: Lane,
    ) -> Result<Option<PartScan>, FileOutcome> {
        if lane.operations_exhausted(&state.counters)
            || lane.opens_exhausted(&state.counters)
            || state.cancel_requested()
        {
            return Err(FileOutcome::Budget);
        }
        let metadata = match stat_optional(&self.fs, directory, &mut state.counters) {
            Ok(Some(metadata)) => metadata,
            Ok(None) => return Ok(None),
            Err(stop) => return Err(stop_outcome(stop)),
        };
        if metadata.file_type().is_symlink() {
            return Err(FileOutcome::Failed(FailureCode::RootOverlap));
        }
        if !metadata.is_dir() {
            return Err(FileOutcome::Failed(FailureCode::RootInvalid));
        }
        let canonical = match canonicalize_counted(&self.fs, directory, &mut state.counters) {
            Ok(canonical) => canonical,
            Err(stop) => return Err(stop_outcome(stop)),
        };
        if !canonical.starts_with(&self.roots.source) {
            return Err(FileOutcome::Failed(FailureCode::RootOverlap));
        }
        let mut scan = PartScan::empty(message.to_path_buf(), message_stamp);
        scan.directory = canonical.clone();
        scan.directory_stamp = FileStamp::of(&metadata);
        match spool_file(&self.roots, &canonical, &metadata, "directory") {
            Ok(stat) => scan.files.push(stat),
            Err(code) => return Err(FileOutcome::Failed(code)),
        }
        state.counters.directory_opens = state.counters.directory_opens.saturating_add(1);
        match self
            .fs
            .read_dir_selected(&canonical, scan.directory_stamp, &mut state.counters)
        {
            Ok(entries) => scan.entries = Some(entries),
            Err(error) if error.kind() == io::ErrorKind::NotFound && !budget_exhausted(&error) => {
                match DirectoryFrontier::source_metadata_if_present(
                    &self.fs,
                    &self.roots,
                    self.source_identity,
                    &canonical,
                    &mut state.counters,
                ) {
                    Ok(None) => return Ok(None),
                    Ok(Some(_)) => return Err(FileOutcome::Failed(FailureCode::SourceChanging)),
                    Err(Stop::Budget | Stop::ValidationBudget) => {
                        self.frontier.validation_budget = true;
                        return Err(FileOutcome::Budget);
                    }
                    Err(stop) => return Err(stop_outcome(stop)),
                }
            }
            Err(error) => {
                self.frontier.validation_budget |= fs::validation_budget_exhausted(&error);
                return Err(stop_outcome(stop_of(error)));
            }
        }
        Ok(Some(scan))
    }

    /// Reads part files through the scan's held iterator, charging every yield, stat and read
    /// against the shared budgets. Budget is checked before the iterator is pulled, and the entry
    /// being processed when the budget ends is kept for the next pass.
    fn advance_part_scan(
        &mut self,
        scan: &mut PartScan,
        state: &mut PassState,
        lane: Lane,
    ) -> ScanStep {
        loop {
            if lane.operations_exhausted(&state.counters) || state.cancel_requested() {
                return ScanStep::Budget;
            }
            let part_path = match scan.deferred.take() {
                Some(path) => path,
                None => {
                    let Some(entries) = scan.entries.as_mut() else {
                        return ScanStep::Done;
                    };
                    let Some(entry) = entries.next() else {
                        return ScanStep::Done;
                    };
                    state.counters.entries = state.counters.entries.saturating_add(1);
                    match entry {
                        Ok(path) => path,
                        Err(error) => {
                            return ScanStep::Failed(FileOutcome::Failed(io_failure(error)));
                        }
                    }
                }
            };
            let is_json = part_path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".json"));
            if !is_json {
                continue;
            }
            let metadata = match source_metadata(&self.fs, &part_path, &mut state.counters) {
                Ok(metadata) => metadata,
                Err(Stop::Budget | Stop::ValidationBudget) => {
                    scan.deferred = Some(part_path);
                    return ScanStep::Budget;
                }
                Err(stop) => return ScanStep::Failed(stop_outcome(stop)),
            };
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                scan.failure = lesser(scan.failure, FailureCode::RootOverlap);
                continue;
            }
            let part_canonical = match canonical_source_file(
                &self.fs,
                &self.roots.source,
                &part_path,
                &metadata,
                &mut state.counters,
            ) {
                Ok(path) => path,
                Err(Stop::Budget | Stop::ValidationBudget) => {
                    scan.deferred = Some(part_path);
                    return ScanStep::Budget;
                }
                Err(stop) => return ScanStep::Failed(stop_outcome(stop)),
            };
            if metadata.len() > MAX_OPENCODE_RECORD_BYTES as u64 {
                state.counters.rejected_records = state.counters.rejected_records.saturating_add(1);
                scan.failure = lesser(scan.failure, FailureCode::RecordTooLarge);
                continue;
            }
            if state.counters.bytes_read.saturating_add(metadata.len()) > lane.bytes() {
                scan.deferred = Some(part_path);
                return ScanStep::Budget;
            }
            state.counters.source_opens = state.counters.source_opens.saturating_add(1);
            let payload = match self.fs.read_bounded(
                &part_canonical,
                read_allowance(lane, &state.counters),
                &mut state.counters,
            ) {
                Ok(payload) => payload,
                Err(error) if budget_exhausted(&error) => {
                    scan.deferred = Some(part_path);
                    return ScanStep::Budget;
                }
                Err(error) => return ScanStep::Failed(FileOutcome::Failed(io_failure(error))),
            };
            let stamp = FileStamp::of(&metadata);
            if payload.before != stamp || payload.before != payload.after {
                return ScanStep::Failed(FileOutcome::Failed(FailureCode::SourceChanging));
            }
            state.counters.rows_read = state.counters.rows_read.saturating_add(1);
            state.counters.bytes_read = state
                .counters
                .bytes_read
                .saturating_add(payload.bytes.len() as u64);
            let Some(part_id) = part_path.file_stem().and_then(|stem| stem.to_str()) else {
                state.counters.rejected_records = state.counters.rejected_records.saturating_add(1);
                scan.failure = lesser(scan.failure, FailureCode::InvalidRecord);
                continue;
            };
            if payload.bytes.len() > MAX_OPENCODE_RECORD_BYTES {
                state.counters.rejected_records = state.counters.rejected_records.saturating_add(1);
                scan.failure = lesser(scan.failure, FailureCode::RecordTooLarge);
                continue;
            }
            match spool_file(
                &self.roots,
                &part_canonical,
                &metadata,
                "opencode_json_part",
            ) {
                Ok(stat) => scan.files.push(stat),
                Err(code) => return ScanStep::Failed(FileOutcome::Failed(code)),
            }
            scan.stamps.push((part_canonical, stamp));
            // Only decoded step-finish parts are kept; the raw payload is dropped here.
            match opencode::decode_step_finish_part(part_id, &payload.bytes) {
                Ok(Some(part)) => {
                    if scan.parts.len() >= crate::limits::MAX_SELECTED_PART_IDS {
                        scan.failure = lesser(scan.failure, FailureCode::LimitExceeded);
                    } else {
                        scan.parts.push(part);
                    }
                }
                Ok(None) => {}
                Err(_) => scan.incomplete = true,
            }
        }
    }

    /// A group is acquired file by file, so it is only trusted if, once every read is done, the
    /// roots, the message, each part and the part directory still carry the identity and stamp
    /// they were read under. Anything else is a mixed generation and is not published.
    fn revalidate(
        &mut self,
        message: &Path,
        message_stamp: FileStamp,
        scan: &mut PartScan,
        state: &mut PassState,
        lane: Lane,
    ) -> Result<bool, Stop> {
        if let Err(outcome) = self.check_file_roots(state) {
            return Err(match outcome {
                FileOutcome::Budget => Stop::Budget,
                _ => Stop::Fail(FailureCode::RootOverlap),
            });
        }
        let directory = scan
            .entries
            .is_some()
            .then_some((scan.directory.clone(), scan.directory_stamp));
        let total = 1 + scan.stamps.len() + usize::from(directory.is_some());
        while scan.revalidated < total {
            if lane.operations_exhausted(&state.counters) || state.cancel_requested() {
                return Err(Stop::Budget);
            }
            let index = scan.revalidated;
            let (path, expected) = match index {
                0 => (message, message_stamp),
                _ if index <= scan.stamps.len() => {
                    let (path, stamp) = &scan.stamps[index - 1];
                    (path.as_path(), *stamp)
                }
                _ => match &directory {
                    Some((path, stamp)) => (path.as_path(), *stamp),
                    None => break,
                },
            };
            let current = source_metadata(&self.fs, path, &mut state.counters)?;
            if FileStamp::of(&current) != expected {
                return Ok(false);
            }
            scan.revalidated += 1;
        }
        Ok(true)
    }
}

enum ScanStep {
    Done,
    Budget,
    Failed(FileOutcome),
}

impl PartScan {
    fn empty(message: PathBuf, message_stamp: FileStamp) -> Self {
        Self {
            message,
            message_stamp,
            directory: PathBuf::new(),
            directory_stamp: message_stamp,
            entries: None,
            deferred: None,
            parts: Vec::new(),
            files: Vec::new(),
            stamps: Vec::new(),
            failure: None,
            incomplete: false,
            revalidated: 0,
        }
    }
}

/// Relative path, record id and format rank of each candidate of a batch.
fn candidate_keys(root: &Path, candidates: &[RecordCandidate]) -> Vec<(PathBuf, String, u8)> {
    candidates
        .iter()
        .filter_map(|candidate| {
            let relative = candidate.canonical_path.strip_prefix(root).ok()?;
            Some((
                relative.to_path_buf(),
                candidate.record_id(),
                candidate.format_rank,
            ))
        })
        .collect()
}

pub(crate) fn pass_report(
    outcome: PassOutcome,
    failure: Option<FailureCode>,
    counters: PassCounters,
    records_committed: u32,
    last_good_ms: Option<i64>,
) -> PassReport {
    PassReport {
        outcome,
        failure,
        counters,
        records_committed,
        last_good_ms,
    }
}

fn root_failure(error: RootError) -> FailureCode {
    match error {
        RootError::InvalidSource | RootError::InvalidData | RootError::HomeRoot => {
            FailureCode::RootInvalid
        }
        RootError::Overlap => FailureCode::RootOverlap,
        RootError::TooLong | RootError::LimitExceeded => FailureCode::LimitExceeded,
    }
}

pub(crate) fn stop_failure(stop: Stop) -> FailureCode {
    match stop {
        Stop::Budget | Stop::ValidationBudget => FailureCode::LimitExceeded,
        Stop::Fail(code) => code,
    }
}

pub(crate) fn store_failure(error: StoreError) -> FailureCode {
    match error {
        StoreError::LimitExceeded => FailureCode::LimitExceeded,
        StoreError::CountOutOfRange | StoreError::InvalidStoredValue => FailureCode::InvalidRecord,
        _ => FailureCode::Store,
    }
}

fn sqlite_open_failure(error: sqlite_ro::OpenError) -> FailureCode {
    match error {
        sqlite_ro::OpenError::Sqlite(code) if code & 0xff == rusqlite::ffi::SQLITE_BUSY => {
            FailureCode::Busy
        }
        sqlite_ro::OpenError::Sqlite(code) if code & 0xff == rusqlite::ffi::SQLITE_NOTADB => {
            FailureCode::NotSqlite
        }
        sqlite_ro::OpenError::Sqlite(code) if code & 0xff == rusqlite::ffi::SQLITE_CORRUPT => {
            FailureCode::Corrupt
        }
        _ => FailureCode::Sqlite,
    }
}

fn io_failure(error: io::Error) -> FailureCode {
    if fs::selected_directory_limit(&error) {
        return FailureCode::LimitExceeded;
    }
    match error.kind() {
        io::ErrorKind::NotFound => FailureCode::SourceChanging,
        io::ErrorKind::InvalidInput => FailureCode::RootOverlap,
        _ => FailureCode::Io,
    }
}

/// One metadata call, charged by the filesystem against the shared per-pass ceiling.
pub(crate) fn source_metadata<F: SourceFs>(
    fs: &F,
    path: &Path,
    counters: &mut PassCounters,
) -> Result<std::fs::Metadata, Stop> {
    fs.metadata(path, counters).map_err(stop_of)
}

/// Like [`source_metadata`] but a missing path is `None`, not a failure.
pub(crate) fn stat_optional<F: SourceFs>(
    fs: &F,
    path: &Path,
    counters: &mut PassCounters,
) -> Result<Option<std::fs::Metadata>, Stop> {
    match fs.metadata(path, counters) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound && !budget_exhausted(&error) => {
            Ok(None)
        }
        Err(error) => Err(stop_of(error)),
    }
}

fn canonicalize_counted<F: SourceFs>(
    fs: &F,
    path: &Path,
    counters: &mut PassCounters,
) -> Result<PathBuf, Stop> {
    fs.canonicalize(path, counters).map_err(stop_of)
}

/// A filesystem error as a stop: the metadata ceiling resumes later, anything else fails.
pub(crate) fn stop_of(error: io::Error) -> Stop {
    if fs::validation_budget_exhausted(&error) {
        Stop::ValidationBudget
    } else if budget_exhausted(&error) {
        Stop::Budget
    } else {
        Stop::Fail(io_failure(error))
    }
}

fn canonical_source_file<F: SourceFs>(
    fs: &F,
    root: &Path,
    path: &Path,
    initial: &std::fs::Metadata,
    counters: &mut PassCounters,
) -> Result<PathBuf, Stop> {
    if initial.file_type().is_symlink() || !initial.is_file() {
        return Err(Stop::Fail(FailureCode::RootOverlap));
    }
    let canonical = canonicalize_counted(fs, path, counters)?;
    if !canonical.starts_with(root) {
        return Err(Stop::Fail(FailureCode::RootOverlap));
    }
    let metadata = source_metadata(fs, &canonical, counters)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Stop::Fail(FailureCode::RootOverlap));
    }
    Ok(canonical)
}

pub(crate) fn root_identity<F: SourceFs>(
    fs: &F,
    path: &Path,
    counters: &mut PassCounters,
) -> Result<RootIdentity, Stop> {
    let metadata = source_metadata(fs, path, counters)?;
    if !metadata.is_dir() {
        return Err(Stop::Fail(FailureCode::RootInvalid));
    }
    Ok(RootIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

pub(crate) fn spool_file(
    roots: &CanonicalRoots,
    path: &Path,
    metadata: &std::fs::Metadata,
    parser_kind: &str,
) -> Result<SpoolFile, FailureCode> {
    let relative_path = path
        .strip_prefix(&roots.source)
        .map_err(|_| FailureCode::RootOverlap)?
        .to_path_buf();
    if relative_path.to_str().is_none() {
        return Err(FailureCode::InvalidRecord);
    }
    Ok(SpoolFile {
        relative_path,
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.len(),
        mtime_ns: FileStamp::of(metadata).mtime_ns,
        parser_kind: parser_kind.to_owned(),
    })
}

fn is_database_name(path: &Path) -> bool {
    is_opencode_database(path)
}

fn is_opencode_database(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.starts_with("opencode") && path.extension().and_then(|ext| ext.to_str()) == Some("db")
}

fn is_part_tree(relative: &Path) -> bool {
    let mut components = relative.components();
    components
        .next()
        .is_some_and(|component| component.as_os_str() == "storage")
        && components
            .next()
            .is_some_and(|component| component.as_os_str() == "part")
        && components.next().is_none()
}

fn message_path(root: &Path, path: &Path) -> Option<(String, String)> {
    let relative = path.strip_prefix(root).ok()?;
    let mut components = relative.components();
    if components.next()?.as_os_str() != "storage" || components.next()?.as_os_str() != "message" {
        return None;
    }
    let session = components.next()?.as_os_str().to_str()?.to_owned();
    let file = components.next()?.as_os_str();
    if components.next().is_some() || Path::new(file).extension()?.to_str()? != "json" {
        return None;
    }
    Some((session, Path::new(file).file_stem()?.to_str()?.to_owned()))
}

// ---------------------------------------------------------------------------------------------
// Engine: the sole owner of at most one Store (DEC-060) and of the per-root runtimes.

/// Returned by [`Engine::pass_until`] when the cancel flag stopped the pass at a budget poll.
/// What the pass committed before the poll stays published; the next pass converges.
#[derive(Debug)]
pub struct PassCancelled(pub PassReport);

/// Why [`Engine::ingest`] stopped: the caller's cancel, or a store failure reading the durable
/// source list, never reported as an empty success.
#[derive(Debug)]
pub enum IngestError {
    Cancelled(PassCancelled),
    Store(StoreError),
}

/// The canonical data path a Store (or claim) is bound to, with the anchor it was reached from.
struct Bound {
    path: PathBuf,
    anchor: DataAnchor,
}

/// One attached root's runtime, by harness.
enum Runtime<F: SourceFs> {
    OpenCode(Box<OpenCodeSource<F>>),
    Codex(Box<CodexSource<F>>),
}

enum Slot<F: SourceFs> {
    Attached(Runtime<F>),
    /// A durable enabled source whose runtime could not be built; the current failure is shown
    /// over its durable status without touching it.
    Unattached {
        code: FailureCode,
        attempted_ms: Option<i64>,
    },
}

/// The runtime of a registered root for its harness, loaded from the store.
#[expect(
    clippy::too_many_arguments,
    reason = "the attach and reattach paths pass the facts each already proved"
)]
fn build_runtime<F: SourceFs>(
    harness: Harness,
    fs: F,
    source_root: &Path,
    data_dir: &Path,
    home: &Path,
    roots: CanonicalRoots,
    source_identity: RootIdentity,
    data_identity: RootIdentity,
    source_id: String,
    store: &mut Store,
) -> Result<Runtime<F>, StoreError> {
    Ok(match harness {
        Harness::OpenCode => {
            let mut source = OpenCodeSource::new(
                fs,
                source_root,
                data_dir,
                home,
                roots,
                source_identity,
                data_identity,
                source_id,
            );
            source.reload(store)?;
            Runtime::OpenCode(Box::new(source))
        }
        Harness::Codex => {
            let mut source = CodexSource::new(
                fs,
                source_root,
                data_dir,
                home,
                roots,
                source_identity,
                data_identity,
                source_id,
            );
            source.reload(store)?;
            Runtime::Codex(Box::new(source))
        }
    })
}

/// A `today_snapshot` request the Engine refuses.
#[derive(Debug, Eq, PartialEq)]
pub enum TodayError {
    Window(WindowError),
    Store(StoreError),
}

/// Whether the canonical `data` path equals, contains or lies inside `root`, by path components.
fn overlaps(data: &Path, root: &Path) -> bool {
    data.starts_with(root) || root.starts_with(data)
}

/// A root as the filesystem resolves it now: canonical path and (device, inode), or `None` when
/// it is absent or unreadable (left to `reattach`).
type Resolved = Option<(PathBuf, (u64, u64))>;

fn resolve<F: SourceFs>(fs: &F, path: &Path) -> Resolved {
    let mut counters = PassCounters::default();
    let canonical = fs.canonicalize(path, &mut counters).ok()?;
    let metadata = fs.metadata(&canonical, &mut counters).ok()?;
    Some((canonical, (metadata.dev(), metadata.ino())))
}

pub struct Engine<F: SourceFs> {
    data_request: PathBuf,
    home: PathBuf,
    store: Option<Store>,
    bound: Option<Bound>,
    sources: BTreeMap<String, Slot<F>>,
    last_store_error: Option<StoreError>,
    /// This Engine claims its data directory (DEC-062) instead of opening unguarded.
    owned: bool,
    /// Declared after `store`, so close, unwind and drop close the SQLite connection and every
    /// history descriptor before the lock is released.
    owner: Option<DataDirOwner>,
}

impl<F: SourceFs> Engine<F> {
    /// Records the requests and does no I/O.
    pub fn open(data_dir: &Path, home: &Path) -> Self {
        Self {
            data_request: data_dir.to_path_buf(),
            home: home.to_path_buf(),
            store: None,
            bound: None,
            sources: BTreeMap::new(),
            last_store_error: None,
            owned: false,
            owner: None,
        }
    }

    pub fn store(&self) -> Option<&Store> {
        self.store.as_ref()
    }

    pub fn store_mut(&mut self) -> Option<&mut Store> {
        self.store.as_mut()
    }

    /// The store error of the last `load_existing` or `attach_opencode` that failed on the store.
    pub fn last_store_error(&self) -> Option<&StoreError> {
        self.last_store_error.as_ref()
    }

    /// Marks this Engine owned and opens existing history (ABI only; the 004 suites never call
    /// it). An existing data directory is claimed before any history or sidecar descriptor
    /// opens; an absent one is neither created nor locked. When `history.sqlite` exists it is
    /// admitted (one bounded committed read, containment of every persisted and resolved root,
    /// then a recheck) before the writable open. On every failure the store stays `None`,
    /// nothing is written and no persisted row changes.
    pub fn load_existing(&mut self, fs: &F) -> Result<(), StoreError> {
        self.last_store_error = None;
        self.owned = true;
        let result = self.load_existing_inner(fs);
        if let Err(error) = &result {
            self.last_store_error = Some(error.clone());
        }
        result
    }

    fn load_existing_inner(&mut self, fs: &F) -> Result<(), StoreError> {
        if self.store.is_some() {
            return Ok(());
        }
        let (data, anchor) =
            discovery::anchor_for(&self.data_request).map_err(|_| StoreError::Io)?;
        if data != anchor.path {
            // The data directory does not exist yet.
            return Ok(());
        }
        if self.owner.is_none() {
            self.owner = Some(DataDirOwner::claim(&data, &anchor, false)?);
        }
        self.bound = Some(Bound { path: data, anchor });
        let history = self
            .owner
            .as_ref()
            .map_or(Ok(false), DataDirOwner::history_exists)?;
        if !history {
            return Ok(());
        }
        self.open_owned(fs, None)
    }

    /// Steps (1)–(3) of admission, or a creating open when no history exists, beneath the
    /// claimed guard. `requested` is a root being attached and joins the containment check.
    fn open_owned(&mut self, fs: &F, requested: Option<&Path>) -> Result<(), StoreError> {
        let (Some(owner), Some(bound)) = (self.owner.as_ref(), self.bound.as_ref()) else {
            return Err(StoreError::Io);
        };
        let (data, anchor) = (bound.path.clone(), bound.anchor.clone());
        let store = if owner.history_exists()? {
            let admission = Store::admit_existing(&data, &anchor, owner)?;
            if let Some(requested) = requested
                && overlaps(&data, requested)
            {
                return Err(StoreError::RootOverlap);
            }
            // Step 2: the persisted canonical paths, even if missing or unreadable, before any
            // root I/O; then each enabled root resolved once.
            if admission
                .roots()
                .iter()
                .any(|root| overlaps(&data, &root.canonical_root))
            {
                return Err(StoreError::RootOverlap);
            }
            let first: Vec<Resolved> = admission
                .roots()
                .iter()
                .map(|root| resolve(fs, &root.canonical_root))
                .collect();
            if first
                .iter()
                .flatten()
                .any(|(canonical, _)| overlaps(&data, canonical))
            {
                return Err(StoreError::RootOverlap);
            }
            // Step 3: every enabled root resolved again must equal step 2.
            let second: Vec<Resolved> = admission
                .roots()
                .iter()
                .map(|root| resolve(fs, &root.canonical_root))
                .collect();
            if second
                .iter()
                .flatten()
                .any(|(canonical, _)| overlaps(&data, canonical))
            {
                return Err(StoreError::RootOverlap);
            }
            if second != first {
                return Err(StoreError::UnsafeFile);
            }
            Store::open_admitted(&data, owner, admission)?
        } else {
            owner.verify_reachable()?;
            Store::open_bound_owned(&data, owner)?
        };
        self.store = Some(store);
        Ok(())
    }

    /// Opens the first Store for `attach_opencode`: unguarded through `Store::open_bound` for
    /// an unowned Engine, beneath a freshly claimed (or already held) guard for an owned one.
    fn open_first(&mut self, fs: &F, roots: &CanonicalRoots) -> Result<(), StoreError> {
        if !self.owned {
            let store = Store::open_bound(&roots.data, &roots.data_anchor)?;
            self.bound = Some(Bound {
                path: roots.data.clone(),
                anchor: roots.data_anchor.clone(),
            });
            self.store = Some(store);
            return Ok(());
        }
        match &self.owner {
            None => {
                self.owner = Some(DataDirOwner::claim(&roots.data, &roots.data_anchor, true)?);
            }
            Some(owner) => {
                // The held directory must still be the one the roots resolve to.
                let same = owner.path() == roots.data
                    && (roots.data_anchor.path != roots.data
                        || owner.identity() == (roots.data_anchor.device, roots.data_anchor.inode));
                if !same {
                    return Err(StoreError::UnsafeFile);
                }
            }
        }
        self.bound = Some(Bound {
            path: roots.data.clone(),
            anchor: roots.data_anchor.clone(),
        });
        // A refusal, containment included, keeps the claim with no Store until close.
        self.open_owned(fs, Some(&roots.source))
    }

    /// Registers `source_root` and builds its runtime, opening the Store first when none is
    /// open. Runs exactly the checks the former single-root engine ran: unauthorized (no I/O),
    /// root validation, source identity, then the Store. An attached root returns its id
    /// without a second runtime.
    pub fn attach_opencode(
        &mut self,
        fs: F,
        source_root: &Path,
        authorization: SourceAuthorization,
        kind: SourceKind,
    ) -> Result<String, PassReport> {
        self.attach(Harness::OpenCode, fs, source_root, authorization, kind)
    }

    /// Registers a Codex root and builds its runtime on the one Store, exactly as
    /// [`Engine::attach_opencode`] does for OpenCode. A root already registered for another
    /// harness is refused `RootInvalid` with no write, in either direction.
    pub fn attach_codex(
        &mut self,
        fs: F,
        source_root: &Path,
        authorization: SourceAuthorization,
        kind: SourceKind,
    ) -> Result<String, PassReport> {
        self.attach(Harness::Codex, fs, source_root, authorization, kind)
    }

    fn attach(
        &mut self,
        harness: Harness,
        fs: F,
        source_root: &Path,
        authorization: SourceAuthorization,
        kind: SourceKind,
    ) -> Result<String, PassReport> {
        self.last_store_error = None;
        if let Some(report) = unauthorized(authorization) {
            return Err(report);
        }
        let mut counters = PassCounters::default();
        let unavailable = |failure: FailureCode, counters: PassCounters| {
            pass_report(PassOutcome::Unavailable, Some(failure), counters, 0, None)
        };
        let roots = match discovery::validate_roots(
            &fs,
            source_root,
            &self.data_request,
            &self.home,
            &mut counters,
        ) {
            Ok(roots) => roots,
            Err(error) => return Err(unavailable(root_failure(error), counters)),
        };
        let source_identity = match root_identity(&fs, &roots.source, &mut counters) {
            Ok(identity) => identity,
            Err(stop) => return Err(unavailable(stop_failure(stop), counters)),
        };
        let opened_here = self.store.is_none();
        if opened_here {
            // Everything beneath the data root is created and opened through a handle bound to
            // the identity validated above, so a swapped path is refused, not followed.
            if let Err(error) = self.open_first(&fs, &roots) {
                self.last_store_error = Some(error);
                return Err(unavailable(FailureCode::Store, counters));
            }
        } else if !self.bound_matches(&roots) {
            return Err(unavailable(FailureCode::Store, counters));
        }
        let Some(store) = self.store.as_mut() else {
            return Err(unavailable(FailureCode::Store, counters));
        };
        let (device, inode) = store.data_identity();
        let data_identity = RootIdentity { device, inode };
        let registration = store.register_harness_source(
            harness,
            &roots.source,
            kind,
            (source_identity.device, source_identity.inode),
        );
        let registration = match registration {
            Ok(registration) => registration,
            // The root is registered for another harness: refused, nothing written.
            Err(StoreError::InvalidRoot) => {
                return Err(unavailable(FailureCode::RootInvalid, counters));
            }
            Err(error) => return Err(self.attach_failed(opened_here, error, counters)),
        };
        let source_id = registration.source_id;
        if matches!(self.sources.get(&source_id), Some(Slot::Attached(_))) {
            return Ok(source_id);
        }
        if !self.sources.contains_key(&source_id) && self.sources.len() >= MAX_REPORTED_SOURCES {
            return Err(unavailable(FailureCode::LimitExceeded, counters));
        }
        let store = self.store.as_mut().expect("the store was just used");
        let runtime = build_runtime(
            harness,
            fs,
            source_root,
            &self.data_request,
            &self.home,
            roots,
            source_identity,
            data_identity,
            source_id.clone(),
            store,
        );
        let runtime = match runtime {
            Ok(runtime) => runtime,
            Err(error) => return Err(self.attach_failed(opened_here, error, counters)),
        };
        self.sources
            .insert(source_id.clone(), Slot::Attached(runtime));
        Ok(source_id)
    }

    /// Whether a re-validated data root is still the one the open Store is bound to.
    fn bound_matches(&self, roots: &CanonicalRoots) -> bool {
        match (&self.bound, &self.store) {
            (Some(bound), Some(store)) => {
                bound.path == roots.data
                    && (roots.data_anchor.device, roots.data_anchor.inode) == store.data_identity()
            }
            _ => false,
        }
    }

    /// A failure after the Store opened: the Store of the attach that opened it is dropped back
    /// to `None` (a held guard stays held) and its error stays `last_store_error`.
    fn attach_failed(
        &mut self,
        opened_here: bool,
        error: StoreError,
        counters: PassCounters,
    ) -> PassReport {
        self.last_store_error = Some(error);
        if opened_here {
            self.store = None;
            if !self.owned {
                self.bound = None;
            }
        }
        pass_report(
            PassOutcome::Unavailable,
            Some(FailureCode::Store),
            counters,
            0,
            None,
        )
    }

    /// The single startup and retry path for a persisted root, for every harness: the runtime is
    /// built for the harness of its durable row. Requires a Store and a durable consent-enabled
    /// row, re-validates the persisted canonical path and identity, and only then registers and
    /// reloads. A failure builds no runtime and writes nothing durable: it
    /// is recorded in the bounded in-memory `Unattached` map, replacing any earlier record.
    pub fn reattach(
        &mut self,
        fs: F,
        source_id: &str,
        attempted_ms: Option<i64>,
    ) -> Result<String, PassReport> {
        let refused = |failure: FailureCode| {
            pass_report(
                PassOutcome::Unavailable,
                Some(failure),
                PassCounters::default(),
                0,
                None,
            )
        };
        let Some(store) = self.store.as_ref() else {
            return Err(refused(FailureCode::Unselected));
        };
        let row = match store.source_row(source_id) {
            Ok(Some(row)) => row,
            _ => return Err(refused(FailureCode::Unselected)),
        };
        match row.consent {
            ConsentState::Enabled => {}
            ConsentState::Denied => return Err(refused(FailureCode::Denied)),
            ConsentState::Undecided => return Err(refused(FailureCode::Unselected)),
        }
        if matches!(self.sources.get(source_id), Some(Slot::Attached(_))) {
            return Ok(source_id.to_owned());
        }
        let mut counters = PassCounters::default();
        let attempt = self.reattach_checked(&fs, &row, &mut counters);
        let (roots, source_identity) = match attempt {
            Ok(checked) => checked,
            Err(code) => {
                self.record_unattached(source_id, code, attempted_ms);
                return Err(pass_report(
                    PassOutcome::Unavailable,
                    Some(code),
                    counters,
                    0,
                    None,
                ));
            }
        };
        let Some(store) = self.store.as_mut() else {
            return Err(refused(FailureCode::Unselected));
        };
        let Some(harness) = Harness::parse(&row.harness) else {
            self.record_unattached(source_id, FailureCode::Store, attempted_ms);
            return Err(refused(FailureCode::Store));
        };
        let (device, inode) = store.data_identity();
        let data_identity = RootIdentity { device, inode };
        let registered = store.register_harness_source(
            harness,
            &roots.source,
            row.kind,
            (source_identity.device, source_identity.inode),
        );
        let runtime = registered.and_then(|registration| {
            build_runtime(
                harness,
                fs,
                &PathBuf::from(&row.canonical_root),
                &self.data_request,
                &self.home,
                roots,
                source_identity,
                data_identity,
                registration.source_id,
                store,
            )
        });
        let Ok(runtime) = runtime else {
            self.record_unattached(source_id, FailureCode::Store, attempted_ms);
            return Err(refused(FailureCode::Store));
        };
        self.sources
            .insert(source_id.to_owned(), Slot::Attached(runtime));
        Ok(source_id.to_owned())
    }

    /// The checks `attach` runs plus the persisted-identity comparison. A different canonical
    /// path or identity (a replacement directory, including a symlink swap) is `RootOverlap`.
    fn reattach_checked(
        &self,
        fs: &F,
        row: &SourceRow,
        counters: &mut PassCounters,
    ) -> Result<(CanonicalRoots, RootIdentity), FailureCode> {
        let persisted = PathBuf::from(&row.canonical_root);
        let roots =
            discovery::validate_roots(fs, &persisted, &self.data_request, &self.home, counters)
                .map_err(root_failure)?;
        let identity = root_identity(fs, &roots.source, counters).map_err(stop_failure)?;
        let same = roots.source == persisted
            && row.root_device.zip(row.root_inode) == Some((identity.device, identity.inode));
        if !same {
            return Err(FailureCode::RootOverlap);
        }
        if !self.bound_matches(&roots) {
            return Err(FailureCode::Store);
        }
        Ok((roots, identity))
    }

    fn record_unattached(&mut self, source_id: &str, code: FailureCode, attempted_ms: Option<i64>) {
        self.sources.insert(
            source_id.to_owned(),
            Slot::Unattached { code, attempted_ms },
        );
    }

    /// Drops a runtime or its recorded failure. The durable row and history are untouched.
    pub fn detach(&mut self, source_id: &str) {
        self.sources.remove(source_id);
    }

    /// Sets a registered source's consent `denied` and detaches it, with no source I/O.
    pub fn deny(&mut self, source_id: &str) -> Result<(), StoreError> {
        let store = self.store.as_mut().ok_or(StoreError::InvalidRoot)?;
        store.set_consent(source_id, ConsentState::Denied)?;
        self.sources.remove(source_id);
        Ok(())
    }

    /// The id of an already registered root, by its stored canonical path or by what `root`
    /// canonicalizes to. `None` when no such source is durable.
    pub fn find_registered(&self, fs: &F, root: &Path) -> Result<Option<String>, StoreError> {
        let Some(store) = self.store.as_ref() else {
            return Ok(None);
        };
        if let Some(id) = store.source_id(root)? {
            return Ok(Some(id));
        }
        let mut counters = PassCounters::default();
        match fs.canonicalize(root, &mut counters) {
            Ok(canonical) => store.source_id(&canonical),
            Err(_) => Ok(None),
        }
    }

    /// Ids of every durable consent-enabled source, ordered by id.
    pub fn enabled_source_ids(&self) -> Result<Vec<String>, StoreError> {
        let Some(store) = self.store.as_ref() else {
            return Ok(Vec::new());
        };
        Ok(store
            .source_rows()?
            .into_iter()
            .filter(|row| row.consent == ConsentState::Enabled)
            .map(|row| row.source_id)
            .collect())
    }

    pub fn is_attached(&self, source_id: &str) -> bool {
        matches!(self.sources.get(source_id), Some(Slot::Attached(_)))
    }

    /// A pass with no cancel flag.
    pub fn pass(
        &mut self,
        source_id: &str,
        authorization: SourceAuthorization,
        now_ms: i64,
    ) -> PassReport {
        match self.pass_until(source_id, authorization, now_ms, &AtomicBool::new(false)) {
            Ok(report) | Err(PassCancelled(report)) => report,
        }
    }

    /// One pass that polls `cancel` only where the pass already polls its budget. An id with no
    /// runtime reports `Unavailable`/`Unselected` with no I/O.
    pub fn pass_until(
        &mut self,
        source_id: &str,
        authorization: SourceAuthorization,
        now_ms: i64,
        cancel: &AtomicBool,
    ) -> Result<PassReport, PassCancelled> {
        if let Some(report) = unauthorized(authorization) {
            return Ok(report);
        }
        let (Some(store), Some(Slot::Attached(runtime))) =
            (self.store.as_mut(), self.sources.get_mut(source_id))
        else {
            return Ok(pass_report(
                PassOutcome::Unavailable,
                Some(FailureCode::Unselected),
                PassCounters::default(),
                0,
                None,
            ));
        };
        match runtime {
            Runtime::OpenCode(source) => source.pass_until(store, authorization, now_ms, cancel),
            Runtime::Codex(source) => source.pass_until(store, authorization, now_ms, cancel),
        }
    }

    /// One ingest over every durable consent-enabled source with the caller's token: an attached
    /// source runs `pass_until`; a missing runtime gets exactly one `reattach` with `now_ms` and
    /// runs only when that succeeds. Denied and undecided sources get no reattach, no pass and
    /// no I/O. A triggered token stops before the next reattach as before the next pass.
    pub fn ingest(
        &mut self,
        mut make_fs: impl FnMut() -> F,
        now_ms: i64,
        cancel: &AtomicBool,
    ) -> Result<(), IngestError> {
        let ids = self.enabled_source_ids().map_err(IngestError::Store)?;
        let authorization = SourceAuthorization {
            selected: true,
            consent: ConsentState::Enabled,
        };
        for id in ids {
            if cancel.load(std::sync::atomic::Ordering::Acquire) {
                return Err(IngestError::Cancelled(PassCancelled(pass_report(
                    PassOutcome::CatchingUp,
                    None,
                    PassCounters::default(),
                    0,
                    None,
                ))));
            }
            if !self.is_attached(&id) && self.reattach(make_fs(), &id, Some(now_ms)).is_err() {
                continue;
            }
            self.pass_until(&id, authorization, now_ms, cancel)
                .map_err(IngestError::Cancelled)?;
        }
        Ok(())
    }

    /// The store holds `source_id` durably; a missing runtime is not missing history.
    fn durable(&self, source_id: &str) -> Result<&Store, StoreError> {
        let store = self.store.as_ref().ok_or(StoreError::InvalidRoot)?;
        if store.has_source(source_id)? {
            Ok(store)
        } else {
            Err(StoreError::InvalidRoot)
        }
    }

    /// Raw durable records of a source when they fit one bounded page; larger histories return
    /// `LimitExceeded` and are read with [`Self::observations_page`]. An id absent from the
    /// Store is `InvalidRoot`.
    pub fn observations(
        &self,
        source_id: &str,
    ) -> Result<Vec<SourceReportedObservation>, StoreError> {
        self.durable(source_id)?.observations(source_id)
    }

    pub fn observations_page(
        &self,
        source_id: &str,
        after: Option<&ObservationCursor>,
        limit: usize,
    ) -> Result<ObservationPage, StoreError> {
        self.durable(source_id)?
            .observations_page(source_id, after, limit)
    }

    /// Bounded numeric projection of the whole durable history of one source.
    pub fn snapshot(
        &self,
        source_id: &str,
        report: &PassReport,
    ) -> Result<SourceSnapshot, StoreError> {
        Ok(SourceSnapshot::new(
            source_id.to_owned(),
            report.outcome,
            report.failure,
            report.counters,
            report.last_good_ms,
            self.durable(source_id)?.source_projection(source_id)?,
        ))
    }

    /// Every durable source as a snapshot entry, with the unattached overlay (outcome
    /// `unavailable`, its failure and attempt time) over a consent-enabled source that has no
    /// runtime. The durable `last_success_ms`, status row and numbers are never replaced.
    pub fn source_entries(&self) -> Result<Vec<SourceEntry>, StoreError> {
        let Some(store) = self.store.as_ref() else {
            return Ok(Vec::new());
        };
        Ok(store
            .source_rows()?
            .into_iter()
            .map(|row| {
                let overlay = match self.sources.get(&row.source_id) {
                    Some(Slot::Unattached { code, attempted_ms })
                        if row.consent == ConsentState::Enabled =>
                    {
                        Some((*code, *attempted_ms))
                    }
                    _ => None,
                };
                let root_display = Path::new(&row.canonical_root)
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let (outcome, last_attempt_ms, last_error_code) = match overlay {
                    Some((code, attempted)) => {
                        (Some(PassOutcome::Unavailable), attempted, Some(code))
                    }
                    None => (row.outcome, row.last_attempt_ms, row.last_error_code),
                };
                SourceEntry {
                    source_id: row.source_id,
                    harness: row.harness,
                    root_display,
                    kind: row.kind,
                    consent: row.consent,
                    outcome,
                    last_attempt_ms,
                    last_success_ms: row.last_success_ms,
                    last_error_code,
                    rejected_count: row.rejected_count,
                    pending_partial: row.pending_partial,
                }
            })
            .collect())
    }

    /// The v1 daily snapshot: the local-day window of `now_ms` in `tz`, every source entry and
    /// each source's projection of the records inside that window. A store-less Engine returns
    /// the window with empty arrays.
    pub fn today_snapshot(&self, tz: &str, now_ms: i64) -> Result<TodaySnapshot, TodayError> {
        let window = Window::local_day(now_ms, tz).map_err(TodayError::Window)?;
        let Some(store) = self.store.as_ref() else {
            return Ok(TodaySnapshot {
                window,
                by_source: Vec::new(),
                source_reported: Vec::new(),
            });
        };
        let by_source = self.source_entries().map_err(TodayError::Store)?;
        let mut source_reported = Vec::with_capacity(by_source.len());
        for entry in &by_source {
            source_reported.push(DailyReported {
                source_id: entry.source_id.clone(),
                projection: store
                    .source_window_projection(&entry.source_id, window.bounds())
                    .map_err(TodayError::Store)?,
            });
        }
        Ok(TodaySnapshot {
            window,
            by_source,
            source_reported,
        })
    }

    #[cfg(feature = "test-faults")]
    pub fn inject_commit_fault(&mut self, point: crate::store::FaultPoint) {
        if let Some(store) = self.store.as_mut() {
            store.inject_fault(point);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::DataAnchor;
    use crate::domain::PassCounters;
    use crate::ingest::fs::RealSourceFs;

    fn work(path: PathBuf) -> DirectoryWork {
        DirectoryWork {
            path,
            depth: 1,
            stat: None,
            restart_blocked: false,
        }
    }

    /// The directory of a held part scan reaching EOF keeps its slot of the shared queue ceiling:
    /// the queue can be filled to the ceiling but never past it, nothing already queued is
    /// dropped, the directory is still pending in the persisted snapshot, and ending the scan
    /// completes it and frees the slot.
    #[test]
    fn a_parked_directory_keeps_its_slot_of_the_queue_ceiling()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().canonicalize()?;
        let held_directory = root.join("held");
        std::fs::create_dir(&held_directory)?;
        let message = held_directory.join("m.json");
        std::fs::write(&message, b"{}")?;
        let mut pending = vec![(held_directory.clone(), 1, false)];
        for index in 0..MAX_FRONTIER_DIRECTORIES - 1 {
            let path = root.join(format!("d{index:04}"));
            std::fs::create_dir(&path)?;
            pending.push((path, 1, false));
        }
        let mut frontier = DirectoryFrontier::new(&root, pending, Vec::new());
        assert_eq!(frontier.snapshot().len(), MAX_FRONTIER_DIRECTORIES);
        let roots = CanonicalRoots {
            source: root.clone(),
            data: root.join("data"),
            data_anchor: DataAnchor {
                path: root.join("data"),
                device: 0,
                inode: 0,
            },
        };
        let mut counters = PassCounters::default();
        // Walk until the held directory's iterator ends while its message scan is held.
        let identity = super::root_identity(&RealSourceFs, &root, &mut counters)
            .map_err(|error| format!("{error:?}"))?;
        for _ in 0..100 {
            match frontier.next(
                &RealSourceFs,
                &roots,
                identity,
                Some(&message),
                &mut counters,
            ) {
                WalkStep::CompletedDirectory(stat) if stat.relative_path == Path::new("held") => {
                    break;
                }
                WalkStep::Capped | WalkStep::Exhausted => return Err("the walk ended early".into()),
                _ => {}
            }
        }
        assert!(
            frontier
                .snapshot()
                .iter()
                .any(|(path, ..)| path == &held_directory),
            "the exhausted directory stays pending while its scan is held"
        );
        assert!(!frontier.is_drained());
        let mut extra = 0;
        while frontier.enqueue(work(root.join(format!("extra{extra}")))) {
            extra += 1;
            assert!(extra <= MAX_FRONTIER_DIRECTORIES, "the ceiling never bites");
        }
        let snapshot = frontier.snapshot();
        assert_eq!(snapshot.len(), MAX_FRONTIER_DIRECTORIES);
        assert!(snapshot.iter().any(|(path, ..)| path == &held_directory));

        frontier.release_parked(Some(&message));
        assert!(
            frontier
                .snapshot()
                .iter()
                .any(|(path, ..)| path == &held_directory),
            "still held"
        );
        frontier.release_parked(None);
        assert!(
            frontier
                .snapshot()
                .iter()
                .all(|(path, ..)| path != &held_directory)
        );
        assert!(
            frontier.enqueue(work(root.join("after"))),
            "the slot is free"
        );
        Ok(())
    }

    /// A directory persisted both completed (its listing finished) and pending (its held scan was
    /// lost) is listed again after a restart.
    #[test]
    fn a_pending_directory_overrides_its_completed_row_on_reconstruction() {
        let root = PathBuf::from("/source");
        let held = root.join("storage/message/s");
        let frontier = DirectoryFrontier::new(
            &root,
            vec![(held.clone(), 3, false)],
            vec![root.clone(), held.clone()],
        );
        assert_eq!(frontier.snapshot(), vec![(held, 3, false)]);
        assert!(!frontier.is_drained());
    }

    fn enabled() -> SourceAuthorization {
        SourceAuthorization {
            selected: true,
            consent: ConsentState::Enabled,
        }
    }

    /// After a first-attach containment refusal, whether that attach took the claim or already
    /// held it, the failed handle keeps its owner claim with no Store until it closes.
    #[test]
    fn first_attach_overlap_keeps_the_owner_claim_until_close()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let base = directory.path().canonicalize()?;
        let (a, b, home) = (base.join("a"), base.join("b"), base.join("home"));
        let data = base.join("x").join("data");
        for path in [&a, &b, &home] {
            std::fs::create_dir(path)?;
        }
        // H2 opens while no data directory exists, so its first attach claims afresh.
        let mut h2: Engine<RealSourceFs> = Engine::open(&data, &home);
        h2.load_existing(&RealSourceFs)?;
        {
            let mut h1: Engine<RealSourceFs> = Engine::open(&data, &home);
            h1.load_existing(&RealSourceFs)?;
            h1.attach_opencode(RealSourceFs, &a, enabled(), SourceKind::Custom)
                .map_err(|report| format!("H1 attach: {report:?}"))?;
        }
        // The persisted root is re-pointed at an ancestor of the data directory.
        std::fs::rename(&a, base.join("a-moved"))?;
        std::os::unix::fs::symlink(base.join("x"), &a)?;
        for attempt in ["claimed here", "already held"] {
            assert!(
                h2.attach_opencode(RealSourceFs, &b, enabled(), SourceKind::Custom)
                    .is_err(),
                "{attempt}"
            );
            assert_eq!(
                h2.last_store_error(),
                Some(&StoreError::RootOverlap),
                "{attempt}"
            );
            assert!(h2.store().is_none(), "{attempt}");
            let mut rival: Engine<RealSourceFs> = Engine::open(&data, &home);
            assert_eq!(
                rival.load_existing(&RealSourceFs),
                Err(StoreError::Busy),
                "{attempt}: the claim is still held"
            );
        }
        drop(h2);
        let mut after: Engine<RealSourceFs> = Engine::open(&data, &home);
        assert_eq!(
            after.load_existing(&RealSourceFs),
            Err(StoreError::RootOverlap),
            "closing released the claim"
        );
        Ok(())
    }

    /// An ingest whose durable source list cannot be read returns that store error, never an
    /// empty success.
    #[test]
    fn ingest_returns_a_source_list_store_error() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let base = directory.path().canonicalize()?;
        let (source, home, data) = (base.join("source"), base.join("home"), base.join("data"));
        std::fs::create_dir(&source)?;
        std::fs::create_dir(&home)?;
        let mut engine: Engine<RealSourceFs> = Engine::open(&data, &home);
        engine
            .attach_opencode(RealSourceFs, &source, enabled(), SourceKind::Custom)
            .map_err(|report| format!("attach: {report:?}"))?;
        // Outside rows past the source bound make the durable list unreadable.
        let outside = rusqlite::Connection::open(data.join("history.sqlite"))?;
        for index in 0..64 {
            outside.execute(
                "INSERT INTO sources(source_id, harness, canonical_root, kind, consent) \
                 VALUES(?1, 'opencode', ?2, 'custom', 'denied')",
                rusqlite::params![format!("{index:032}"), format!("/outside/{index}")],
            )?;
        }
        drop(outside);
        let result = engine.ingest(|| RealSourceFs, 1, &AtomicBool::new(false));
        assert!(
            matches!(result, Err(IngestError::Store(StoreError::LimitExceeded))),
            "{result:?}"
        );
        Ok(())
    }
}
