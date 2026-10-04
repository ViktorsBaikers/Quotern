pub mod fs;
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

use crate::adapters::opencode::StepFinishPart;
use crate::adapters::opencode::{self, DecodeError, ReadBudget, ResolveError};
use crate::discovery::{self, CanonicalRoots, RootError};
use crate::domain::{
    ConsentState, FailureCode, PassCounters, PassOutcome, PassReport, RecordCandidate,
    SourceAuthorization, SourceKind, SourceReportedObservation,
};
use crate::limits::{
    MAX_DIRECTORY_DEPTH, MAX_DIRECTORY_ENTRIES, MAX_DIRECTORY_OPENS, MAX_FRONTIER_DIRECTORIES,
    MAX_HEADER_READS, MAX_KNOWN_PATHS_PER_PASS, MAX_METADATA_CALLS, MAX_OPEN_DIRECTORIES,
    MAX_OPENCODE_RECORD_BYTES, MAX_PATH_BYTES, MAX_SOURCE_BYTES_PER_PASS,
    MAX_SOURCE_DATABASES_PER_PASS, MAX_SQLITE_ROWS_PER_PASS,
};
use crate::snapshot::{ObservationCursor, ObservationPage, SourceSnapshot};
use crate::store::{
    CommitRequest, DiscardRequest, FileFailure, PendingMark, ProgressUpdate, SpoolFile, StageBatch,
    StageRequest, Store, StoreError, retry_outcome,
};

use self::fs::{DirEntries, FileStamp, SourceFs, budget_exhausted};

/// Iterator slots held by the directory frontier; the synchronous JSON-part iterator is the
/// remaining one of `MAX_OPEN_DIRECTORIES`, so held iterators never exceed the ceiling.
const FRONTIER_SLOTS: usize = MAX_OPEN_DIRECTORIES - 1;

/// Metadata calls kept back from a database read for the four-sidecar identity proof after it.
const IDENTITY_PROOF_STATS: u32 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RootIdentity {
    device: u64,
    inode: u64,
}

/// Why a unit of work stopped: the shared per-pass budget ended (resume later) or a real failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stop {
    Budget,
    Fail(FailureCode),
}

/// Operation budget of one traversal lane. The reserved current-file lane gets half of every
/// ceiling while a historical backlog exists; the historical lane may use the full ceiling, so
/// whatever the current lane leaves unused transfers to it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Lane {
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

    fn bytes(self) -> u64 {
        MAX_SOURCE_BYTES_PER_PASS / u64::from(self.divisor())
    }

    /// Whether this lane may still open another directory.
    fn opens_exhausted(self, counters: &PassCounters) -> bool {
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
    fn exhausted(self, counters: &PassCounters) -> bool {
        self.operations_exhausted(counters)
            || (self == Self::Current && self.opens_exhausted(counters))
    }
}

struct DirectoryWork {
    path: PathBuf,
    depth: usize,
    stat: Option<SpoolFile>,
    restart_blocked: bool,
}

struct ActiveDirectory {
    path: PathBuf,
    depth: usize,
    entries: DirEntries,
    stat: SpoolFile,
    entries_read: u32,
}

/// A yielded directory entry. `replay` marks one already counted in an earlier pass.
struct Entry {
    path: PathBuf,
    depth: usize,
    replay: bool,
}

enum WalkStep {
    Entry(Entry),
    CompletedDirectory(SpoolFile),
    /// A directory could not be listed or described; it is dropped from this sweep.
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

struct DirectoryFrontier {
    pending: VecDeque<DirectoryWork>,
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
    /// Exhausted directories kept pending for a held part scan; they count against the queue
    /// ceiling exactly as they did while active.
    parked: Vec<ParkedDirectory>,
}

impl DirectoryFrontier {
    fn new(root: &Path, pending: Vec<(PathBuf, usize, bool)>, completed: Vec<PathBuf>) -> Self {
        let mut frontier = Self {
            pending: VecDeque::new(),
            active: Vec::new(),
            scheduled: HashSet::new(),
            completed: completed.into_iter().collect(),
            deferred: None,
            turn: 0,
            source: 0,
            capped: false,
            parked: Vec::new(),
            restart_blocked: false,
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
        if frontier.pending.is_empty() && frontier.completed.is_empty() {
            frontier.enqueue(DirectoryWork {
                path: root.to_path_buf(),
                depth: 0,
                stat: None,
                restart_blocked: false,
            });
        }
        frontier
    }

    fn begin_pass(&mut self) {
        self.capped = false;
    }

    fn enqueue(&mut self, work: DirectoryWork) -> bool {
        if work.restart_blocked {
            self.restart_blocked = true;
        }
        if self.completed.contains(&work.path) || self.scheduled.contains(&work.path) {
            return true;
        }
        if self.pending.len() + self.active.len() + self.parked.len() >= MAX_FRONTIER_DIRECTORIES {
            self.capped = true;
            return false;
        }
        self.scheduled.insert(work.path.clone());
        self.pending.push_back(work);
        true
    }

    fn defer(&mut self, mut entry: Entry) {
        entry.replay = true;
        self.deferred = Some(entry);
    }

    /// The queue ceiling refused a child of the directory that yielded the latest entry. That
    /// listing goes to the back of the queue, in place (the combined count is unchanged), and is
    /// read again from its beginning once the directories ahead of it have drained, so the child
    /// and every later sibling are found when room exists instead of being dropped.
    fn requeue_source(&mut self) {
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

    fn mark_complete(&mut self, path: PathBuf) {
        self.completed.insert(path.clone());
        self.scheduled.insert(path);
    }

    fn snapshot(&self) -> Vec<(PathBuf, usize, bool)> {
        let mut directories =
            Vec::with_capacity(self.pending.len() + self.active.len() + self.parked.len());
        directories.extend(
            self.pending
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

    fn is_drained(&self) -> bool {
        self.pending.is_empty()
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

    /// `held` is the message whose part scan is held open: its parent directory is parked, not
    /// completed, when its iterator ends.
    fn next<F: SourceFs>(
        &mut self,
        fs: &F,
        roots: &CanonicalRoots,
        held: Option<&Path>,
        counters: &mut PassCounters,
    ) -> WalkStep {
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
                None => match source_metadata(fs, &work.path, counters) {
                    Ok(metadata) if metadata.is_dir() => {
                        match spool_file(roots, &work.path, &metadata, "directory") {
                            Ok(stat) => stat,
                            Err(code) => {
                                self.scheduled.remove(&work.path);
                                return WalkStep::Error(code);
                            }
                        }
                    }
                    Ok(_) => {
                        self.scheduled.remove(&work.path);
                        continue;
                    }
                    Err(Stop::Budget) => {
                        self.pending.push_front(work);
                        self.capped = true;
                        return WalkStep::Capped;
                    }
                    Err(Stop::Fail(code)) => {
                        self.scheduled.remove(&work.path);
                        return WalkStep::Error(code);
                    }
                },
            };
            counters.directory_opens = counters.directory_opens.saturating_add(1);
            match fs.read_dir(&work.path, counters) {
                Ok(entries) => self.active.push(ActiveDirectory {
                    path: work.path,
                    depth: work.depth,
                    entries,
                    stat,
                    entries_read: 0,
                }),
                Err(error) if budget_exhausted(&error) => {
                    self.pending.push_front(work);
                    self.capped = true;
                    return WalkStep::Capped;
                }
                Err(error) => {
                    self.scheduled.remove(&work.path);
                    return WalkStep::Error(io_failure(error));
                }
            }
        }
        if self.active.is_empty() {
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
                self.scheduled.remove(&active.path);
                self.turn = 0;
                WalkStep::Error(io_failure(error))
            }
            None => {
                let active = self.active.remove(index);
                self.turn = 0;
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
struct PassState {
    counters: PassCounters,
    candidates: Vec<RecordCandidate>,
    files: Vec<SpoolFile>,
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
}

fn lesser(current: Option<FailureCode>, code: FailureCode) -> Option<FailureCode> {
    match current {
        Some(existing) if existing.as_str() <= code.as_str() => Some(existing),
        _ => Some(code),
    }
}

impl PassState {
    fn reject(&mut self, code: FailureCode) {
        self.rejection = lesser(self.rejection, code);
    }

    fn skip(&mut self, code: FailureCode) {
        self.skipped = lesser(self.skipped, code);
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

pub struct OpenCodeEngine<F: SourceFs> {
    fs: F,
    source_request: PathBuf,
    data_request: PathBuf,
    home: PathBuf,
    roots: CanonicalRoots,
    source_identity: RootIdentity,
    data_identity: RootIdentity,
    store: Store,
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

fn unauthorized(authorization: SourceAuthorization) -> Option<PassReport> {
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

impl<F: SourceFs> OpenCodeEngine<F> {
    pub fn open(
        fs: F,
        source_root: &Path,
        data_dir: &Path,
        home: &Path,
        authorization: SourceAuthorization,
        kind: SourceKind,
    ) -> Result<Self, PassReport> {
        if let Some(report) = unauthorized(authorization) {
            return Err(report);
        }
        let mut counters = PassCounters::default();
        let unavailable = |failure: FailureCode, counters: PassCounters| {
            pass_report(PassOutcome::Unavailable, Some(failure), counters, 0, None)
        };
        let roots = match discovery::validate_roots(&fs, source_root, data_dir, home, &mut counters)
        {
            Ok(roots) => roots,
            Err(error) => return Err(unavailable(root_failure(error), counters)),
        };
        let source_identity = match root_identity(&fs, &roots.source, &mut counters) {
            Ok(identity) => identity,
            Err(stop) => return Err(unavailable(stop_failure(stop), counters)),
        };
        // Everything beneath the data root is created and opened through a handle bound to the
        // identity validated above, so a path swapped since validation is refused, not followed.
        let store = match Store::open_bound(&roots.data, &roots.data_anchor) {
            Ok(store) => store,
            Err(_) => return Err(unavailable(FailureCode::Store, counters)),
        };
        let (device, inode) = store.data_identity();
        let data_identity = RootIdentity { device, inode };
        let mut engine = Self {
            fs,
            source_request: source_root.to_path_buf(),
            data_request: data_dir.to_path_buf(),
            home: home.to_path_buf(),
            frontier: DirectoryFrontier::new(&roots.source, Vec::new(), Vec::new()),
            roots,
            source_identity,
            data_identity,
            store,
            source_id: String::new(),
            generation: 0,
            failures: BTreeMap::new(),
            needs_reload: true,
            needs_reset: false,
            part_scan: None,
            terminal_cursor: None,
        };
        let registration = engine.store.register_source(
            &engine.roots.source,
            kind,
            (source_identity.device, source_identity.inode),
        );
        match registration {
            Ok(registration) => engine.source_id = registration.source_id,
            Err(_) => return Err(unavailable(FailureCode::Store, counters)),
        }
        if engine.reload().is_err() {
            return Err(unavailable(FailureCode::Store, counters));
        }
        Ok(engine)
    }

    pub fn pass(&mut self, authorization: SourceAuthorization, now_ms: i64) -> PassReport {
        if let Some(report) = unauthorized(authorization) {
            return report;
        }
        if self.needs_reset {
            match self
                .store
                .reset_acquisition(&self.source_id, self.generation)
            {
                Ok(()) | Err(StoreError::StaleGeneration) => self.needs_reset = false,
                Err(error) => {
                    return self.report(
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
            && let Err(error) = self.reload()
        {
            return self.report(
                PassOutcome::Partial,
                Some(store_failure(error)),
                PassCounters::default(),
                0,
            );
        }
        match self.store.retry_state(&self.source_id) {
            Ok(retry) => {
                if retry.next_retry_ms.is_some_and(|next| now_ms < next) {
                    // Backing off after a source change, idle or busy refusal: no source I/O
                    // until the deadline.
                    let reason = retry.reason.unwrap_or(FailureCode::SourceChanging);
                    return self.report(
                        retry_outcome(reason, retry.change_count),
                        Some(reason),
                        PassCounters::default(),
                        0,
                    );
                }
            }
            Err(error) => {
                return self.report(
                    PassOutcome::Partial,
                    Some(store_failure(error)),
                    PassCounters::default(),
                    0,
                );
            }
        }
        let mut state = PassState::default();
        match self.check_roots(&mut state.counters) {
            RootCheck::Valid => {}
            RootCheck::Budget => {
                return self.report(
                    PassOutcome::CatchingUp,
                    Some(FailureCode::LimitExceeded),
                    state.counters,
                    0,
                );
            }
            RootCheck::Conflict => {
                return self.report(
                    PassOutcome::Unavailable,
                    Some(FailureCode::RootOverlap),
                    state.counters,
                    0,
                );
            }
        }
        if self.frontier.restart_blocked {
            return self.report_restart_blocked(state.counters, now_ms);
        }
        self.frontier.begin_pass();
        state.source_seen = match self
            .store
            .generation_has_source_files(&self.source_id, self.generation)
        {
            Ok(seen) => seen,
            Err(error) => {
                return self.report(
                    PassOutcome::Partial,
                    Some(store_failure(error)),
                    state.counters,
                    0,
                );
            }
        };
        self.resume_part_scan(&mut state);
        // Every directory of this generation has been listed and each message in them read, so
        // another refresh of the known messages could only start one more held scan and postpone
        // finalization forever; what is unfinished (held scan, failures, databases) still resumes.
        let drained = self.frontier.is_drained();
        self.current_lane(&mut state, drained);
        if !state.changing && !state.caught_up {
            self.walk(&mut state);
        }
        self.finish(state, now_ms)
    }

    /// Reserved lane: persisted failed and known source paths are revalidated before general
    /// discovery, so a current mutable record is read even when it sits behind a huge backlog.
    fn current_lane(&mut self, state: &mut PassState, drained: bool) {
        let mut relatives: Vec<PathBuf> = self.failures.keys().cloned().collect();
        match self
            .store
            .known_paths(&self.source_id, MAX_KNOWN_PATHS_PER_PASS)
        {
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
            if Lane::Current.exhausted(&state.counters) || state.changing || state.caught_up {
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
                Err(Stop::Budget) => break,
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
            let outcome = self.process_file(&path, &metadata, state, Lane::Current);
            // The reserved lane running out of budget ends only itself; discovery still runs.
            if matches!(outcome, FileOutcome::Budget) {
                break;
            }
            if let Flow::Stop = self.apply(&path, outcome, state, None) {
                break;
            }
        }
    }

    /// The message whose part directory is held open is finished first, with the reserved lane's
    /// half of the budget, so every pass advances it and no other message can take its slot.
    fn resume_part_scan(&mut self, state: &mut PassState) {
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
            Err(Stop::Budget) => return,
            Err(Stop::Fail(code)) => {
                self.part_scan = None;
                state.skip(code);
                return;
            }
        };
        let outcome = self.process_file(&path, &metadata, state, Lane::Current);
        if matches!(outcome, FileOutcome::Budget) {
            return;
        }
        let _ = self.apply(&path, outcome, state, None);
    }

    /// Historical lane: bounded round-robin traversal of the directory frontier.
    fn walk(&mut self, state: &mut PassState) {
        loop {
            if Lane::Full.exhausted(&state.counters) {
                state.caught_up = true;
                break;
            }
            let held = self.part_scan.as_ref().map(|scan| scan.message.as_path());
            let step = self
                .frontier
                .next(&self.fs, &self.roots, held, &mut state.counters);
            match step {
                WalkStep::Exhausted => break,
                WalkStep::Capped => {
                    state.caught_up = true;
                    break;
                }
                WalkStep::Error(code) => state.skip(code),
                WalkStep::CompletedDirectory(stat) => state.files.push(stat),
                WalkStep::Entry(entry) => {
                    if let Flow::Stop = self.visit(entry, state) {
                        break;
                    }
                }
            }
        }
    }

    fn visit(&mut self, entry: Entry, state: &mut PassState) -> Flow {
        if entry.path.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES {
            state.skip(FailureCode::LimitExceeded);
            return Flow::Continue;
        }
        let metadata = match source_metadata(&self.fs, &entry.path, &mut state.counters) {
            Ok(metadata) => metadata,
            Err(Stop::Budget) => {
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
        let outcome = self.process_file(&path, &metadata, state, Lane::Full);
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
        path: &Path,
        metadata: &std::fs::Metadata,
        state: &mut PassState,
        lane: Lane,
    ) -> FileOutcome {
        if !state.visited.insert(path.to_path_buf()) {
            return FileOutcome::Skipped;
        }
        if is_opencode_database(path) {
            self.process_database(path, metadata, state, lane)
        } else if let Some((session_id, message_id)) = message_path(&self.roots.source, path) {
            self.process_json_message(&session_id, &message_id, path, metadata, state, lane)
        } else {
            FileOutcome::Skipped
        }
    }

    fn finish(&mut self, mut state: PassState, now_ms: i64) -> PassReport {
        if state.changing {
            let paths: Vec<PathBuf> = state.changing_path.iter().cloned().collect();
            return self.changed(state.counters, now_ms, &paths, &[]);
        }
        // A parked directory is complete once its scan is no longer held.
        self.frontier
            .release_parked(self.part_scan.as_ref().map(|scan| scan.message.as_path()));
        // Work that outlives the pass (a held part scan, an unfinished current-lane file) keeps
        // the generation open: the pass is catching up, never idle, consistent or terminal.
        if state.current_incomplete || self.part_scan.is_some() {
            state.caught_up = true;
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
        let mut failure = database_failure
            .or(other_failure)
            .or(state.rejection)
            .or(state.skipped);
        let root_complete = self.frontier.is_drained() && !state.caught_up;
        // Any database failure is unavailable whatever else was read, so the classification
        // never depends on which sibling happened to be visited first.
        let outcome = if database_failure.is_some() {
            PassOutcome::Unavailable
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
            return self.finish_unavailable(state, prospective, database_failure, failure, now_ms);
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
        let frontier = self.frontier.snapshot();
        let conflicts = candidate_keys(&self.roots.source, &state.candidates);
        if root_complete && state.source_seen {
            match self.completed_databases_unchanged(&mut state) {
                Ok(true) => {}
                Ok(false) => return self.changed(state.counters, now_ms, &[], &conflicts),
                Err(Stop::Budget) => {
                    // Not enough budget left to prove the staged databases unchanged: stay
                    // catching up and prove it with a fresh budget next pass.
                    state.caught_up = true;
                }
                Err(Stop::Fail(code)) => {
                    return self.report(PassOutcome::Partial, Some(code), state.counters, 0);
                }
            }
        }
        let root_complete = root_complete && !state.caught_up;
        let outcome = if state.caught_up && outcome == PassOutcome::Consistent {
            PassOutcome::CatchingUp
        } else {
            outcome
        };
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
            let mut staged = match self.store.load_staged_candidates(
                &self.source_id,
                &self.roots.source,
                self.generation,
            ) {
                Ok(staged) => staged,
                Err(error) => return self.store_failed(error, state.counters),
            };
            staged.extend(state.candidates.iter().cloned());
            if let Err(ResolveError::SourceChanging) = opencode::resolve_candidates(staged) {
                return self.changed(state.counters, now_ms, &[], &conflicts);
            }
            let terminal = failure.is_none() && !state.incomplete;
            let result = self.store.commit_generation(CommitRequest {
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
                        summary.outcome,
                        summary.failure,
                        state.counters,
                        summary.records_committed,
                    )
                }
                Err(StoreError::StageConflict) => {
                    self.changed(state.counters, now_ms, &[], &conflicts)
                }
                Err(error) => {
                    // A failed finalization invalidates the acquisition it would have published:
                    // drop the staged evidence so every source is read again before trusting it.
                    self.invalidate_acquisition();
                    self.store_failed(error, state.counters)
                }
            };
        }
        let result = self.store.stage_scan(StageRequest {
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
        });
        match result {
            Ok(summary) => {
                self.failures = prospective;
                self.report(outcome, failure, state.counters, summary.records_committed)
            }
            Err(StoreError::StageConflict) => self.changed(state.counters, now_ms, &[], &conflicts),
            Err(error) => self.store_failed(error, state.counters),
        }
    }

    /// An unavailable pass publishes nothing and advances nothing: only the failure bookkeeping
    /// (and a durable idle/busy retry) is recorded. The in-memory traversal that ran ahead of
    /// the store is rebuilt from what is durable.
    fn finish_unavailable(
        &mut self,
        state: PassState,
        prospective: BTreeMap<PathBuf, FailureCode>,
        database_failure: Option<FailureCode>,
        failure: Option<FailureCode>,
        now_ms: i64,
    ) -> PassReport {
        let backoff = database_failure
            .filter(|code| matches!(code, FailureCode::SourceIdle | FailureCode::Busy));
        let result = self.store.stage_scan(StageRequest {
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
                if self.reload().is_err() {
                    self.needs_reload = true;
                }
                self.report(PassOutcome::Unavailable, failure, state.counters, 0)
            }
            Err(error) => self.store_failed(error, state.counters),
        }
    }

    /// Terminal proof that no database read earlier in this generation changed since: its
    /// identity set (and, without a write-ahead log, its main-file stamp) must still be the one
    /// it was read under. Databases not in `source_files` yet are covered.
    fn completed_databases_unchanged(&mut self, state: &mut PassState) -> Result<bool, Stop> {
        // A database read in this pass may differ from what earlier pages proved: start over.
        if state.database_opens > 0 {
            self.terminal_cursor = None;
        }
        loop {
            let page = self
                .store
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
    fn invalidate_acquisition(&mut self) {
        self.part_scan = None;
        match self
            .store
            .reset_acquisition(&self.source_id, self.generation)
        {
            Ok(()) | Err(StoreError::StaleGeneration) => {}
            Err(_) => self.needs_reset = true,
        }
    }

    /// Source identity changed under an acquisition: drop acquisition-local state, keep the
    /// committed baseline flagged pending (restoring groups a competing acquisition touched), and
    /// back off before touching the source again.
    fn changed(
        &mut self,
        counters: PassCounters,
        now_ms: i64,
        paths: &[PathBuf],
        conflicts: &[(PathBuf, String, u8)],
    ) -> PassReport {
        self.part_scan = None;
        let result = self.store.discard_generation(DiscardRequest {
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
                if self.reload().is_err() {
                    self.needs_reload = true;
                }
                self.report(
                    summary.outcome,
                    Some(FailureCode::SourceChanging),
                    counters,
                    0,
                )
            }
            Err(error) => self.store_failed(error, counters),
        }
    }

    /// A store write failed. Whatever it left durable is the truth: reload from it rather than
    /// continuing from in-memory state that may be ahead of, or behind, what was committed.
    fn store_failed(&mut self, error: StoreError, counters: PassCounters) -> PassReport {
        if self.reload().is_err() {
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
        self.report(outcome, Some(store_failure(error)), counters, 0)
    }

    /// Rebuilds all acquisition-local state from the store: generation, frontier, completed
    /// directories and unresolved file failures.
    fn reload(&mut self) -> Result<(), StoreError> {
        self.needs_reload = true;
        let generation = self.store.generation(&self.source_id)?;
        let pending = self
            .store
            .load_frontier(&self.source_id, &self.roots.source, generation)?;
        let completed = self.store.load_completed_directories(
            &self.source_id,
            &self.roots.source,
            generation,
        )?;
        let failures = self
            .store
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
        for (path, expected) in [
            (&self.roots.source, self.source_identity),
            (&self.roots.data, self.data_identity),
        ] {
            match root_identity(&self.fs, path, counters) {
                Ok(identity) if identity == expected => {}
                Err(Stop::Budget) => return RootCheck::Budget,
                _ => return RootCheck::Conflict,
            }
        }
        RootCheck::Valid
    }

    fn report_restart_blocked(&mut self, counters: PassCounters, now_ms: i64) -> PassReport {
        let mut completed = match self.store.load_completed_directories(
            &self.source_id,
            &self.roots.source,
            self.generation,
        ) {
            Ok(completed) => completed,
            Err(error) => {
                return self.report(
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
            match self
                .store
                .load_frontier(&self.source_id, &self.roots.source, self.generation)
            {
                Ok(frontier) => frontier,
                Err(error) => {
                    return self.report(
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
        let result = self.store.stage_scan(StageRequest {
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
                PassOutcome::Partial,
                Some(FailureCode::LimitExceeded),
                counters,
                0,
            ),
            Err(error) => self.store_failed(error, counters),
        }
    }

    #[cfg(feature = "test-faults")]
    pub fn inject_commit_fault(&mut self, point: crate::store::FaultPoint) {
        self.store.inject_fault(point);
    }

    /// Raw durable records of this source when they fit one bounded page; larger histories
    /// return `LimitExceeded` and are read with [`Self::observations_page`].
    pub fn observations(&self) -> Result<Vec<SourceReportedObservation>, StoreError> {
        self.store.observations(&self.source_id)
    }

    pub fn observations_page(
        &self,
        after: Option<&ObservationCursor>,
        limit: usize,
    ) -> Result<ObservationPage, StoreError> {
        self.store.observations_page(&self.source_id, after, limit)
    }

    /// Bounded numeric projection of the whole durable history of this source.
    pub fn snapshot(&self, report: &PassReport) -> Result<SourceSnapshot, StoreError> {
        Ok(SourceSnapshot::new(
            self.source_id.clone(),
            report.outcome,
            report.failure,
            report.counters,
            report.last_good_ms,
            self.store.source_projection(&self.source_id)?,
        ))
    }

    fn report(
        &self,
        outcome: PassOutcome,
        failure: Option<FailureCode>,
        counters: PassCounters,
        records: u32,
    ) -> PassReport {
        let last_good_ms = self.store.last_success_ms(&self.source_id).ok().flatten();
        pass_report(outcome, failure, counters, records, last_good_ms)
    }
}

fn stop_outcome(stop: Stop) -> FileOutcome {
    match stop {
        Stop::Budget => FileOutcome::Budget,
        Stop::Fail(code) => FileOutcome::Failed(code),
    }
}

impl<F: SourceFs> OpenCodeEngine<F> {
    fn process_database(
        &mut self,
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
        match self.check_roots(&mut state.counters) {
            RootCheck::Valid => {}
            RootCheck::Budget => return FileOutcome::Budget,
            RootCheck::Conflict => return FileOutcome::Failed(FailureCode::RootOverlap),
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
            Err(FailureCode::LimitExceeded) => return FileOutcome::Budget,
            Err(code) => return FileOutcome::Failed(code),
        };
        let Ok(relative) = canonical.strip_prefix(&self.roots.source) else {
            return FileOutcome::Failed(FailureCode::RootOverlap);
        };
        let relative = relative.to_path_buf();
        // A saved cursor and its staged candidates belong to the database and sidecar set they
        // were read under; any other set means the source changed under the sweep.
        let identity = before.key();
        let cursor = match self
            .store
            .saved_progress(&self.source_id, &relative, self.generation)
        {
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
            return FileOutcome::Budget;
        }
        state.counters.source_opens = state.counters.source_opens.saturating_add(1);
        state.database_opens += 1;
        let meter = sqlite_ro::MetadataMeter::begin(allowance);
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
            ),
            Err(error) => Err(sqlite_open_failure(error)),
        };
        let (used, refused) = meter.state();
        drop(meter);
        state.counters.stat_calls = state.counters.stat_calls.saturating_add(used);
        if refused {
            // A physical operation was refused for lack of allowance: the read is discarded and
            // retried whole with a fresh budget.
            return FileOutcome::Budget;
        }
        let batch = match read {
            Ok(batch) => batch,
            Err(code) => return FileOutcome::Failed(code),
        };
        match sqlite_ro::identity_unchanged(&self.fs, &canonical, before, &mut state.counters) {
            Ok(true) => {}
            Ok(false) => return FileOutcome::Changing,
            Err(FailureCode::LimitExceeded) => return FileOutcome::Budget,
            Err(code) => return FileOutcome::Failed(code),
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
        match self.check_roots(&mut state.counters) {
            RootCheck::Valid => {}
            RootCheck::Budget => return FileOutcome::Budget,
            RootCheck::Conflict => return FileOutcome::Failed(FailureCode::RootOverlap),
        }
        state.counters.source_opens = state.counters.source_opens.saturating_add(1);
        let read = match self.fs.read_bounded(
            &canonical,
            read_allowance(lane, &state.counters),
            &mut state.counters,
        ) {
            Ok(read) => read,
            Err(error) => return stop_outcome(stop_of(error)),
        };
        state.counters.bytes_read = state
            .counters
            .bytes_read
            .saturating_add(read.bytes.len() as u64);
        state.counters.rows_read = state.counters.rows_read.saturating_add(1);
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
            Err(Stop::Budget) => {
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
        if lane.operations_exhausted(&state.counters) || lane.opens_exhausted(&state.counters) {
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
        match self.fs.read_dir(&canonical, &mut state.counters) {
            Ok(entries) => scan.entries = Some(entries),
            Err(error) if error.kind() == io::ErrorKind::NotFound && !budget_exhausted(&error) => {
                return Ok(None);
            }
            Err(error) => return Err(stop_outcome(stop_of(error))),
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
            if lane.operations_exhausted(&state.counters) {
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
                Err(Stop::Budget) => {
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
                Err(Stop::Budget) => {
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
        &self,
        message: &Path,
        message_stamp: FileStamp,
        scan: &mut PartScan,
        state: &mut PassState,
        lane: Lane,
    ) -> Result<bool, Stop> {
        match self.check_roots(&mut state.counters) {
            RootCheck::Valid => {}
            RootCheck::Budget => return Err(Stop::Budget),
            RootCheck::Conflict => return Err(Stop::Fail(FailureCode::RootOverlap)),
        }
        let directory = scan
            .entries
            .is_some()
            .then_some((scan.directory.clone(), scan.directory_stamp));
        let total = 1 + scan.stamps.len() + usize::from(directory.is_some());
        while scan.revalidated < total {
            if lane.operations_exhausted(&state.counters) {
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

fn pass_report(
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

fn stop_failure(stop: Stop) -> FailureCode {
    match stop {
        Stop::Budget => FailureCode::LimitExceeded,
        Stop::Fail(code) => code,
    }
}

fn store_failure(error: StoreError) -> FailureCode {
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
    match error.kind() {
        io::ErrorKind::NotFound => FailureCode::SourceChanging,
        io::ErrorKind::InvalidInput => FailureCode::RootOverlap,
        _ => FailureCode::Io,
    }
}

/// One metadata call, charged by the filesystem against the shared per-pass ceiling.
fn source_metadata<F: SourceFs>(
    fs: &F,
    path: &Path,
    counters: &mut PassCounters,
) -> Result<std::fs::Metadata, Stop> {
    fs.metadata(path, counters).map_err(stop_of)
}

/// Like [`source_metadata`] but a missing path is `None`, not a failure.
fn stat_optional<F: SourceFs>(
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
fn stop_of(error: io::Error) -> Stop {
    if budget_exhausted(&error) {
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

fn root_identity<F: SourceFs>(
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

fn spool_file(
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
        for _ in 0..100 {
            match frontier.next(&RealSourceFs, &roots, Some(&message), &mut counters) {
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
}
