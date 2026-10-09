//! Codex rollout JSONL as source-reported usage (DEC-077, origin unverified).
//!
//! Redesigned from the openai/codex 335c7f8 record contract (b12ac84 recheck); no upstream code
//! is ported. Only `token_usage_record` lines whose `thread_id` equals the file's own first-line
//! `session_meta` id become rows; `session_id` (the root thread) never decides ownership. Copied
//! fork prefixes, appended headers and foreign first lines fail closed, and pre-record legacy
//! `token_count` lines only widen the file's uncovered range. `token_count` values are never
//! stored or counted.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use serde::Deserialize;
use serde::de::{self, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};

use crate::discovery::{self, CanonicalRoots, RootError};
use crate::domain::{
    CodexHeaderEra, CodexHeaderState, CodexRecordState, CodexTailState, FailureCode, PassCounters,
    PassOutcome, PassReport, SourceAuthorization, bounded, is_valid_id_component,
};
use crate::ingest::fs::{FileStamp, SourceFs};
use crate::ingest::jsonl::{self, Remainder};
use crate::ingest::{
    DirectoryFrontier, DirectoryWork, Entry, Lane, PassCancelled, RootIdentity, Stop, WalkStep,
    lesser, pass_report, root_identity, source_metadata, spool_file, stat_optional, stop_of,
    store_failure, unauthorized,
};
use crate::limits::{
    MAX_DIRECTORY_DEPTH, MAX_JSONL_LINE_BYTES, MAX_KNOWN_PATHS_PER_PASS, MAX_PATH_BYTES,
    MAX_RECORD_ID_BYTES, MAX_RECORD_ID_COMPONENT_BYTES, MAX_SOURCE_TIMESTAMP_MS, MAX_TOKEN_COUNT,
};
use crate::store::{CodexFile, CodexPassRequest, CodexRecord, SpoolFile, Store, StoreError};

// ---------------------------------------------------------------------------------------------
// Line decoding

/// A string of at most `N` bytes, or `None` for anything else (absent, null, another type or
/// longer). Never fails the enclosing line.
#[derive(Default)]
struct Lenient<const N: usize>(Option<String>);

impl<'de, const N: usize> Deserialize<'de> for Lenient<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Text<const N: usize>;

        impl<'de, const N: usize> Visitor<'de> for Text<N> {
            type Value = Option<String>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("any value")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok((value.len() <= N).then(|| value.to_owned()))
            }

            fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
                Ok(None)
            }

            fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
                Ok(None)
            }

            fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> {
                Ok(None)
            }

            fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
                Ok(None)
            }

            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(None)
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(None)
            }
        }

        deserializer.deserialize_any(Text::<N>).map(Self)
    }
}

/// One reported counter: absent (or null), an integer in `0..=MAX_TOKEN_COUNT`, or invalid
/// (negative, fractional, too large or not a number).
#[derive(Clone, Copy, Default)]
enum Counter {
    #[default]
    Absent,
    Value(u64),
    Invalid,
}

impl<'de> Deserialize<'de> for Counter {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Number;

        impl<'de> Visitor<'de> for Number {
            type Value = Counter;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a token count")
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Counter, E> {
                Ok(if value <= MAX_TOKEN_COUNT {
                    Counter::Value(value)
                } else {
                    Counter::Invalid
                })
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Counter, E> {
                Ok(u64::try_from(value).map_or(Counter::Invalid, |value| {
                    if value <= MAX_TOKEN_COUNT {
                        Counter::Value(value)
                    } else {
                        Counter::Invalid
                    }
                }))
            }

            fn visit_f64<E: de::Error>(self, _: f64) -> Result<Counter, E> {
                Ok(Counter::Invalid)
            }

            fn visit_str<E: de::Error>(self, _: &str) -> Result<Counter, E> {
                Ok(Counter::Invalid)
            }

            fn visit_bool<E: de::Error>(self, _: bool) -> Result<Counter, E> {
                Ok(Counter::Invalid)
            }

            fn visit_unit<E: de::Error>(self) -> Result<Counter, E> {
                Ok(Counter::Absent)
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Counter, A::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(Counter::Invalid)
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Counter, A::Error> {
                while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(Counter::Invalid)
            }
        }

        deserializer.deserialize_any(Number)
    }
}

/// Every line's envelope; the payload is skipped here and decoded only for the kinds that matter.
#[derive(Deserialize)]
struct Head {
    #[serde(default)]
    timestamp: Lenient<64>,
    #[serde(rename = "type", default)]
    kind: Lenient<64>,
}

#[derive(Deserialize)]
#[serde(bound(deserialize = "P: Deserialize<'de>"))]
struct Line<P> {
    #[serde(deserialize_with = "object")]
    payload: P,
}

#[derive(Deserialize)]
struct MetaPayload {
    #[serde(deserialize_with = "component")]
    id: String,
    #[serde(default)]
    forked_from_id: Option<IgnoredAny>,
    #[serde(default)]
    cli_version: Lenient<64>,
}

#[derive(Deserialize)]
struct RecordPayload {
    #[serde(deserialize_with = "component")]
    thread_id: String,
    #[serde(deserialize_with = "component")]
    session_id: String,
    #[serde(deserialize_with = "component")]
    response_id: String,
    #[serde(deserialize_with = "object")]
    usage: Usage,
}

#[derive(Deserialize)]
struct Usage {
    #[serde(default)]
    input_tokens: Counter,
    #[serde(default)]
    cached_input_tokens: Counter,
    #[serde(default)]
    cache_write_input_tokens: Counter,
    #[serde(default)]
    output_tokens: Counter,
    #[serde(default)]
    reasoning_output_tokens: Counter,
    #[serde(default)]
    total_tokens: Counter,
}

#[derive(Deserialize)]
struct EventPayload {
    #[serde(rename = "type", default)]
    kind: Lenient<32>,
    #[serde(default)]
    info: Option<IgnoredAny>,
}

/// Preserve raw field duplicates while requiring the documented JSON object shape.
fn object<'de, D: Deserializer<'de>, T: Deserialize<'de>>(deserializer: D) -> Result<T, D::Error> {
    struct Object<T>(std::marker::PhantomData<T>);

    impl<'de, T: Deserialize<'de>> Visitor<'de> for Object<T> {
        type Value = T;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("an object")
        }

        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
            T::deserialize(de::value::MapAccessDeserializer::new(map))
        }
    }

    deserializer.deserialize_map(Object(std::marker::PhantomData))
}

/// An id string within the component byte bound; validity is checked after decoding.
fn component<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    bounded::text(deserializer, MAX_RECORD_ID_COMPONENT_BYTES)
}

/// UTC milliseconds of an RFC 3339 line timestamp inside the accepted calendar range.
fn instant(timestamp: Option<&str>) -> Option<i64> {
    let parsed: jiff::Timestamp = timestamp?.parse().ok()?;
    let millis = parsed.as_millisecond();
    (0..=MAX_SOURCE_TIMESTAMP_MS)
        .contains(&millis)
        .then_some(millis)
}

// ---------------------------------------------------------------------------------------------
// Coverage era (DEC-078 (3))

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Identifier {
    Numeric(u64),
    Alphanumeric(String),
}

/// A semantic version without its build metadata: core, then prerelease identifiers.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Version {
    core: (u64, u64, u64),
    prerelease: Vec<Identifier>,
}

impl Version {
    fn parse(text: &str) -> Option<Self> {
        let text = match text.split_once('+') {
            Some((version, build)) => {
                if !build.split('.').all(|part| {
                    !part.is_empty()
                        && part
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                }) {
                    return None;
                }
                version
            }
            None => text,
        };
        let (core, prerelease) = match text.split_once('-') {
            Some((core, prerelease)) => (core, Some(prerelease)),
            None => (text, None),
        };
        let numeric = |part: &str| -> Option<u64> {
            let leading_zero = part.len() > 1 && part.starts_with('0');
            (!part.is_empty() && !leading_zero && part.bytes().all(|byte| byte.is_ascii_digit()))
                .then(|| part.parse().ok())
                .flatten()
        };
        let mut parts = core.split('.');
        let core = (
            numeric(parts.next()?)?,
            numeric(parts.next()?)?,
            numeric(parts.next()?)?,
        );
        if parts.next().is_some() {
            return None;
        }
        let mut identifiers = Vec::new();
        if let Some(prerelease) = prerelease {
            for part in prerelease.split('.') {
                let valid = !part.is_empty()
                    && part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
                if !valid {
                    return None;
                }
                identifiers.push(if part.bytes().all(|byte| byte.is_ascii_digit()) {
                    Identifier::Numeric(numeric(part)?)
                } else {
                    Identifier::Alphanumeric(part.to_owned())
                });
            }
        }
        Some(Self {
            core,
            prerelease: identifiers,
        })
    }

    /// Semantic-version precedence: a release outranks every prerelease of its core; numeric
    /// identifiers compare numerically and rank below alphanumeric ones; a shorter list of equal
    /// identifiers ranks lower.
    fn at_least(&self, other: &Self) -> bool {
        use std::cmp::Ordering;
        let order = self.core.cmp(&other.core).then_with(|| {
            match (self.prerelease.is_empty(), other.prerelease.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => self.prerelease.cmp(&other.prerelease),
            }
        });
        order != Ordering::Less
    }
}

/// `record` from 0.153.0-alpha.1 on, the first release that persists each record before its
/// `token_count`; `legacy` below it or when `cli_version` is missing or not a semantic version.
fn era(cli_version: Option<&str>) -> CodexHeaderEra {
    let first = Version {
        core: (0, 153, 0),
        prerelease: vec![
            Identifier::Alphanumeric("alpha".to_owned()),
            Identifier::Numeric(1),
        ],
    };
    match cli_version.and_then(Version::parse) {
        Some(version) if version.at_least(&first) => CodexHeaderEra::Record,
        _ => CodexHeaderEra::Legacy,
    }
}

// ---------------------------------------------------------------------------------------------
// Per-file classification

/// The parse of one file's new lines, continued from its stored state.
struct FileParse {
    header_id: Option<String>,
    header_state: Option<CodexHeaderState>,
    header_era: Option<CodexHeaderEra>,
    record_state: CodexRecordState,
    uncovered: Option<(i64, i64)>,
    records: Vec<CodexRecord>,
    rejected: u32,
    rejection: Option<FailureCode>,
}

impl FileParse {
    fn from(file: &CodexFile) -> Self {
        Self {
            header_id: file.header_id.clone(),
            header_state: file.header_state,
            header_era: file.header_era,
            record_state: file.record_state,
            uncovered: file.uncovered,
            records: Vec::new(),
            rejected: 0,
            rejection: None,
        }
    }

    fn reject(&mut self, code: FailureCode) {
        self.rejected = self.rejected.saturating_add(1);
        self.rejection = lesser(self.rejection, code);
    }

    /// Widens the uncovered range by an unadmitted usage line's instant; an unusable timestamp
    /// widens it to the whole calendar.
    fn uncover(&mut self, timestamp: Option<&str>) {
        let (from, to) = instant(timestamp).map_or((0, MAX_SOURCE_TIMESTAMP_MS), |at| (at, at));
        self.uncovered = Some(match self.uncovered {
            Some((low, high)) => (low.min(from), high.max(to)),
            None => (from, to),
        });
    }

    fn admitted(&self) -> bool {
        matches!(
            self.header_state,
            Some(CodexHeaderState::Own | CodexHeaderState::OwnForked)
        )
    }

    fn first_line(&mut self, line: &[u8]) {
        let header = serde_json::from_slice::<Head>(line)
            .ok()
            .filter(|head| head.kind.0.as_deref() == Some("session_meta"))
            .and_then(|_| serde_json::from_slice::<Line<MetaPayload>>(line).ok())
            .filter(|meta| is_valid_id_component(&meta.payload.id));
        match header {
            Some(meta) => {
                self.header_state = Some(if meta.payload.forked_from_id.is_some() {
                    CodexHeaderState::OwnForked
                } else {
                    CodexHeaderState::Own
                });
                self.header_era = Some(era(meta.payload.cli_version.0.as_deref()));
                self.header_id = Some(meta.payload.id);
            }
            None => {
                self.header_state = Some(CodexHeaderState::ForeignFirstLine);
                self.header_era = None;
                self.header_id = None;
                self.line(line);
            }
        }
        self.record_state = CodexRecordState::None;
    }

    fn line(&mut self, line: &[u8]) {
        let Ok(head) = serde_json::from_slice::<Head>(line) else {
            if self.admitted() {
                self.uncover(None);
            }
            self.reject(FailureCode::InvalidRecord);
            return;
        };
        let timestamp = head.timestamp.0.as_deref();
        match head.kind.0.as_deref() {
            Some("session_meta") => self.session_meta(line),
            Some("token_usage_record") => self.record(line, timestamp),
            Some("event_msg") => {
                let token_count =
                    serde_json::from_slice::<Line<EventPayload>>(line).is_ok_and(|event| {
                        event.payload.kind.0.as_deref() == Some("token_count")
                            && event.payload.info.is_some()
                    });
                // A legacy writer persisted no record: its token_count before the first own
                // record is usage that cannot be admitted. A record-era token_count follows its
                // record, so it never affects coverage. A file without an own header has no era
                // and fails closed like legacy.
                let before_own = self.record_state != CodexRecordState::Own;
                if token_count && before_own && self.header_era != Some(CodexHeaderEra::Record) {
                    self.uncover(timestamp);
                }
            }
            _ => {}
        }
    }

    fn session_meta(&mut self, line: &[u8]) {
        if !self.admitted() {
            return;
        }
        let id = serde_json::from_slice::<Line<MetaPayload>>(line)
            .ok()
            .map(|meta| meta.payload.id);
        if id.is_some() && id == self.header_id {
            return;
        }
        if self.header_state == Some(CodexHeaderState::OwnForked)
            && self.record_state != CodexRecordState::Own
        {
            // The copied parent header of a fork's inherited prefix.
            self.record_state = CodexRecordState::Prefix;
        } else {
            self.header_state = Some(CodexHeaderState::AppendedHeader);
        }
    }

    fn record(&mut self, line: &[u8], timestamp: Option<&str>) {
        if !self.admitted() {
            self.uncover(timestamp);
            return;
        }
        let Ok(record) = serde_json::from_slice::<Line<RecordPayload>>(line) else {
            self.uncover(timestamp);
            self.reject(FailureCode::InvalidRecord);
            return;
        };
        let record = record.payload;
        if !is_valid_id_component(&record.thread_id) {
            self.uncover(timestamp);
            self.reject(FailureCode::InvalidRecord);
            return;
        }
        if Some(&record.thread_id) != self.header_id.as_ref() {
            // Another thread's record, copied into this file: never stored or counted.
            if self.record_state == CodexRecordState::None {
                self.record_state = CodexRecordState::Inherited;
            }
            return;
        }
        self.record_state = CodexRecordState::Own;
        let Some(occurred_at_ms) = instant(timestamp) else {
            self.uncover(timestamp);
            self.reject(FailureCode::InvalidRecord);
            return;
        };
        if !is_valid_id_component(&record.session_id)
            || !is_valid_id_component(&record.response_id)
            || record.session_id.len() + record.response_id.len() > MAX_RECORD_ID_BYTES
        {
            self.uncover(timestamp);
            self.reject(FailureCode::InvalidRecord);
            return;
        }
        let usage = record.usage;
        let counters = [
            usage.input_tokens,
            usage.output_tokens,
            usage.reasoning_output_tokens,
            usage.cached_input_tokens,
            usage.cache_write_input_tokens,
            usage.total_tokens,
        ];
        let mut values = [None; 6];
        for (slot, counter) in values.iter_mut().zip(counters) {
            match counter {
                Counter::Absent => {}
                Counter::Value(value) => *slot = Some(value),
                Counter::Invalid => {
                    self.uncover(timestamp);
                    self.reject(FailureCode::InvalidNumber);
                    return;
                }
            }
        }
        self.records.push(CodexRecord {
            session_id: record.session_id,
            response_id: record.response_id,
            occurred_at_ms,
            values,
        });
    }
}

// ---------------------------------------------------------------------------------------------
// Runtime

#[cfg(feature = "test-faults")]
thread_local! {
    static FILE_COMMIT_HOOK: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        const { std::cell::RefCell::new(None) };
    static LINE_HOOK: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Test boundary: runs `hook` on this thread after each committed Codex file, the deterministic
/// in-flight trigger for cancellation between files.
#[cfg(feature = "test-faults")]
pub fn set_file_commit_hook(hook: Option<Box<dyn FnMut()>>) {
    FILE_COMMIT_HOOK.with(|slot| *slot.borrow_mut() = hook);
}

/// Test boundary: runs on this thread before each Codex line's cancellation poll.
#[cfg(feature = "test-faults")]
pub fn set_line_hook(hook: Option<Box<dyn FnMut()>>) {
    LINE_HOOK.with(|slot| *slot.borrow_mut() = hook);
}

fn after_file_commit() {
    #[cfg(feature = "test-faults")]
    {
        let taken = FILE_COMMIT_HOOK.with(|slot| slot.borrow_mut().take());
        if let Some(mut hook) = taken {
            hook();
            FILE_COMMIT_HOOK.with(|slot| {
                let mut slot = slot.borrow_mut();
                if slot.is_none() {
                    *slot = Some(hook);
                }
            });
        }
    }
}

/// What one Codex pass gathers besides the per-file commits it already made.
struct PassState<'a> {
    counters: PassCounters,
    cancel: &'a AtomicBool,
    cancelled: bool,
    visited: HashMap<PathBuf, (FileStamp, FileOutcome)>,
    revalidated: Vec<PathBuf>,
    files: Vec<SpoolFile>,
    verified_files: usize,
    rejection: Option<FailureCode>,
    skipped: Option<FailureCode>,
    incomplete: bool,
    caught_up: bool,
    records_committed: u32,
}

impl PassState<'_> {
    fn cancel_requested(&mut self) -> bool {
        if self.cancel.load(std::sync::atomic::Ordering::Acquire) {
            self.cancelled = true;
        }
        self.cancelled
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

#[derive(Clone, Copy)]
enum FileOutcome {
    /// Read and committed; `more` means bytes remain beyond this pass's read.
    Done {
        more: bool,
    },
    /// Nothing new since the stored state: metadata only.
    Unchanged,
    Budget,
    Cancelled,
    Failed(FailureCode),
}

enum Flow {
    Continue,
    Stop,
}

/// The runtime of one registered Codex root.
pub(crate) struct CodexSource<F: SourceFs> {
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
    needs_reload: bool,
}

/// Where a path sits in the Codex tree: `sessions/**` and `archived_sessions/*` only.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Area {
    /// A directory that may hold rollouts: the root's `sessions`, any directory beneath it, or
    /// the root's `archived_sessions`.
    Directory,
    /// A `*.jsonl` file beneath `sessions` or directly in `archived_sessions`.
    Rollout,
    /// Anything else, including every other root entry (`auth.json`, `history.jsonl`, ...): never
    /// described or opened.
    Outside,
}

fn area(relative: &Path) -> Area {
    let parts: Vec<&std::ffi::OsStr> = relative.iter().collect();
    let jsonl = relative
        .extension()
        .is_some_and(|extension| extension == "jsonl");
    match parts.as_slice() {
        [name] if *name == "sessions" || *name == "archived_sessions" => Area::Directory,
        [first, _] if *first == "archived_sessions" && jsonl => Area::Rollout,
        [first, .., _] if *first == "sessions" && jsonl => Area::Rollout,
        [first, .., _] if *first == "sessions" => Area::Directory,
        _ => Area::Outside,
    }
}

impl<F: SourceFs> CodexSource<F> {
    #[expect(
        clippy::too_many_arguments,
        reason = "one call site per attach path; each argument is a fact the caller already proved"
    )]
    pub(crate) fn new(
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
            needs_reload: true,
        }
    }

    /// Rebuilds the generation and frontier from the store. Directories that were being listed
    /// are listed again from their beginning; completed ones stay completed.
    pub(crate) fn reload(&mut self, store: &Store) -> Result<(), StoreError> {
        self.needs_reload = true;
        let generation = store.generation(&self.source_id)?;
        let pending = store.load_frontier(&self.source_id, &self.roots.source, generation)?;
        let completed =
            store.load_completed_directories(&self.source_id, &self.roots.source, generation)?;
        self.generation = generation;
        self.frontier = DirectoryFrontier::new(&self.roots.source, pending, completed);
        self.needs_reload = false;
        Ok(())
    }

    /// One pass. The cancel flag is polled between records and files; only whole files are
    /// committed, each in its own transaction.
    pub(crate) fn pass_until(
        &mut self,
        store: &mut Store,
        authorization: SourceAuthorization,
        now_ms: i64,
        cancel: &AtomicBool,
    ) -> Result<PassReport, PassCancelled> {
        if let Some(report) = unauthorized(authorization) {
            return Ok(report);
        }
        let mut state = PassState {
            counters: PassCounters::default(),
            cancel,
            cancelled: false,
            visited: HashMap::new(),
            revalidated: Vec::new(),
            files: Vec::new(),
            verified_files: 0,
            rejection: None,
            skipped: None,
            incomplete: false,
            caught_up: false,
            records_committed: 0,
        };
        let report = self.pass(store, &mut state, now_ms);
        if state.cancelled {
            Err(PassCancelled(report))
        } else {
            Ok(report)
        }
    }

    fn pass(&mut self, store: &mut Store, state: &mut PassState<'_>, now_ms: i64) -> PassReport {
        if self.needs_reload
            && let Err(error) = self.reload(store)
        {
            return self.report(
                store,
                PassOutcome::Partial,
                Some(store_failure(error)),
                state,
            );
        }
        match self.check_roots(&mut state.counters) {
            Ok(()) => {}
            Err(Stop::Budget | Stop::ValidationBudget) => {
                return self.report(
                    store,
                    PassOutcome::CatchingUp,
                    Some(FailureCode::LimitExceeded),
                    state,
                );
            }
            Err(Stop::Fail(code)) => {
                return self.report(store, PassOutcome::Unavailable, Some(code), state);
            }
        }
        self.frontier.begin_pass();
        let walked = self
            .current_lane(store, state, now_ms)
            .and_then(|()| self.walk(store, state, now_ms));
        if let Err(error) = walked {
            // A file commit failed: what is durable is the truth, so the frontier that ran ahead
            // of it is rebuilt from the store before the next pass.
            self.needs_reload = true;
            let outcome = match error {
                StoreError::InvalidStoredValue
                | StoreError::CountOutOfRange
                | StoreError::Sqlite => PassOutcome::Unavailable,
                _ => PassOutcome::Partial,
            };
            return self.report(store, outcome, Some(store_failure(error)), state);
        }
        self.finish(store, state, now_ms)
    }

    fn check_roots(&self, counters: &mut PassCounters) -> Result<(), Stop> {
        match discovery::validate_roots(
            &self.fs,
            &self.source_request,
            &self.data_request,
            &self.home,
            counters,
        ) {
            Ok(roots) if roots == self.roots => {}
            Err(RootError::LimitExceeded) => return Err(Stop::Budget),
            _ => return Err(Stop::Fail(FailureCode::RootOverlap)),
        }
        self.check_identities(counters)
    }

    fn check_identities(&self, counters: &mut PassCounters) -> Result<(), Stop> {
        for (path, expected) in [
            (&self.roots.source, self.source_identity),
            (&self.roots.data, self.data_identity),
        ] {
            match root_identity(&self.fs, path, counters) {
                Ok(identity) if identity == expected => {}
                Err(Stop::Budget | Stop::ValidationBudget) => return Err(Stop::Budget),
                _ => return Err(Stop::Fail(FailureCode::RootOverlap)),
            }
        }
        Ok(())
    }

    /// The reserved lane: persisted known files, then the dated `sessions/YYYY/MM/DD`
    /// directories the injected clock can name in any zone (its UTC date and the dates 14 hours
    /// either side), listed directly, so a current file is read whatever the backlog.
    fn current_lane(
        &mut self,
        store: &mut Store,
        state: &mut PassState<'_>,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        let known = match store.known_codex_paths(&self.source_id, MAX_KNOWN_PATHS_PER_PASS) {
            Ok(known) => known,
            Err(_) => {
                state.skip(FailureCode::Store);
                Vec::new()
            }
        };
        for relative in known {
            if Lane::Current.exhausted(&state.counters) || state.cancel_requested() {
                return Ok(());
            }
            let path = self.roots.source.join(&relative);
            let metadata = match stat_optional(&self.fs, &path, &mut state.counters) {
                Ok(Some(metadata)) if metadata.is_file() => metadata,
                Ok(_) => continue,
                Err(stop @ (Stop::Budget | Stop::ValidationBudget)) => {
                    self.frontier.validation_budget |= stop == Stop::ValidationBudget;
                    self.frontier.validation_retry |= stop == Stop::ValidationBudget;
                    return Ok(());
                }
                Err(Stop::Fail(code)) => {
                    state.skip(code);
                    continue;
                }
            };
            state.revalidated.push(relative);
            match self.process_file(store, &path, &metadata, state, Lane::Current, now_ms)? {
                FileOutcome::Done { more: true } | FileOutcome::Budget => {
                    state.caught_up = true;
                    return Ok(());
                }
                FileOutcome::Cancelled => return Ok(()),
                FileOutcome::Failed(code) => state.skip(code),
                FileOutcome::Done { more: false } | FileOutcome::Unchanged => {}
            }
        }
        for directory in dated_directories(now_ms) {
            let path = self.roots.source.join(&directory);
            if Lane::Current.exhausted(&state.counters) || state.cancel_requested() {
                return Ok(());
            }
            let metadata = match stat_optional(&self.fs, &path, &mut state.counters) {
                Ok(Some(metadata)) if metadata.is_dir() => metadata,
                Ok(_) => continue,
                Err(stop @ (Stop::Budget | Stop::ValidationBudget)) => {
                    self.frontier.validation_budget |= stop == Stop::ValidationBudget;
                    self.frontier.validation_retry |= stop == Stop::ValidationBudget;
                    return Ok(());
                }
                Err(Stop::Fail(code)) => {
                    state.skip(code);
                    continue;
                }
            };
            state.counters.directory_opens = state.counters.directory_opens.saturating_add(1);
            let entries = match self.fs.read_dir_selected(
                &path,
                FileStamp::of(&metadata),
                &mut state.counters,
            ) {
                Ok(entries) => entries,
                Err(error) => match stop_of(error) {
                    stop @ (Stop::Budget | Stop::ValidationBudget) => {
                        self.frontier.validation_budget |= stop == Stop::ValidationBudget;
                        self.frontier.validation_retry |= stop == Stop::ValidationBudget;
                        return Ok(());
                    }
                    Stop::Fail(code) => {
                        state.skip(code);
                        continue;
                    }
                },
            };
            let mut entries = entries;
            loop {
                if Lane::Current.exhausted(&state.counters) || state.cancel_requested() {
                    return Ok(());
                }
                let Some(entry) = entries.next() else {
                    break;
                };
                state.counters.entries = state.counters.entries.saturating_add(1);
                let Ok(entry) = entry else {
                    state.skip(FailureCode::Io);
                    break;
                };
                let in_area = entry
                    .strip_prefix(&self.roots.source)
                    .is_ok_and(|relative| area(relative) == Area::Rollout);
                if !in_area {
                    continue;
                }
                let metadata = match source_metadata(&self.fs, &entry, &mut state.counters) {
                    Ok(metadata) if metadata.is_file() => metadata,
                    Ok(_) => continue,
                    Err(stop @ (Stop::Budget | Stop::ValidationBudget)) => {
                        self.frontier.validation_budget |= stop == Stop::ValidationBudget;
                        self.frontier.validation_retry |= stop == Stop::ValidationBudget;
                        return Ok(());
                    }
                    Err(Stop::Fail(code)) => {
                        state.skip(code);
                        continue;
                    }
                };
                match self.process_file(store, &entry, &metadata, state, Lane::Current, now_ms)? {
                    FileOutcome::Done { more: true } | FileOutcome::Budget => {
                        state.caught_up = true;
                        return Ok(());
                    }
                    FileOutcome::Cancelled => return Ok(()),
                    FileOutcome::Failed(code) => state.skip(code),
                    FileOutcome::Done { more: false } | FileOutcome::Unchanged => {}
                }
            }
        }
        Ok(())
    }

    /// The historical lane: bounded round-robin traversal of the persisted frontier.
    fn walk(
        &mut self,
        store: &mut Store,
        state: &mut PassState<'_>,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        loop {
            if Lane::Full.exhausted(&state.counters) || state.cancel_requested() {
                state.caught_up = true;
                return Ok(());
            }
            match self.frontier.next(
                &self.fs,
                &self.roots,
                self.source_identity,
                None,
                &mut state.counters,
            ) {
                WalkStep::Exhausted => return Ok(()),
                WalkStep::Capped => {
                    state.caught_up = true;
                    return Ok(());
                }
                WalkStep::Error(code) => state.skip(code),
                WalkStep::CompletedDirectory(stat) => state.files.push(stat),
                WalkStep::Entry(entry) => {
                    if let Flow::Stop = self.visit(store, entry, state, now_ms)? {
                        return Ok(());
                    }
                }
            }
        }
    }

    fn visit(
        &mut self,
        store: &mut Store,
        entry: Entry,
        state: &mut PassState<'_>,
        now_ms: i64,
    ) -> Result<Flow, StoreError> {
        let Ok(relative) = entry.path.strip_prefix(&self.roots.source) else {
            state.skip(FailureCode::RootOverlap);
            return Ok(Flow::Continue);
        };
        let place = area(relative);
        if place == Area::Outside {
            return Ok(Flow::Continue);
        }
        if entry.path.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES {
            state.skip(FailureCode::LimitExceeded);
            return Ok(Flow::Continue);
        }
        let metadata = match DirectoryFrontier::source_metadata_if_present(
            &self.fs,
            &self.roots,
            self.source_identity,
            &entry.path,
            &mut state.counters,
        ) {
            Ok(Some(metadata)) => metadata,
            Ok(None) => return Ok(Flow::Continue),
            Err(stop @ (Stop::Budget | Stop::ValidationBudget)) => {
                self.frontier.validation_budget |= stop == Stop::ValidationBudget;
                self.frontier.validation_retry |= stop == Stop::ValidationBudget;
                state.caught_up = true;
                self.frontier.defer(entry);
                return Ok(Flow::Stop);
            }
            Err(Stop::Fail(code)) => {
                state.skip(code);
                self.frontier.defer(entry);
                state.caught_up = true;
                return Ok(Flow::Stop);
            }
        };
        // A symlink is an alias, never followed: its target is read where it lives, if inside.
        if metadata.file_type().is_symlink() {
            return Ok(Flow::Continue);
        }
        if metadata.is_dir() {
            if place == Area::Directory {
                self.visit_directory(entry, &metadata, state);
            }
            return Ok(Flow::Continue);
        }
        if !metadata.is_file() || place != Area::Rollout {
            return Ok(Flow::Continue);
        }
        match spool_file(&self.roots, &entry.path, &metadata, "codex_jsonl") {
            Ok(stat) => state.files.push(stat),
            Err(code) => {
                state.skip(code);
                return Ok(Flow::Continue);
            }
        }
        let path = entry.path.clone();
        Ok(
            match self.process_file(store, &path, &metadata, state, Lane::Full, now_ms)? {
                FileOutcome::Done { more: false } | FileOutcome::Unchanged => Flow::Continue,
                FileOutcome::Failed(code) => {
                    state.skip(code);
                    self.frontier.retry_source();
                    state.caught_up = true;
                    Flow::Continue
                }
                FileOutcome::Done { more: true } => {
                    self.frontier.retry_source();
                    state.caught_up = true;
                    Flow::Continue
                }
                FileOutcome::Budget | FileOutcome::Cancelled => {
                    state.caught_up = true;
                    self.frontier.defer(entry);
                    Flow::Stop
                }
            },
        )
    }

    fn visit_directory(
        &mut self,
        entry: Entry,
        metadata: &std::fs::Metadata,
        state: &mut PassState<'_>,
    ) {
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

    /// Reads one file from its stored offset (or from 0 when it was replaced, truncated or
    /// rewritten) and commits its records and state in one transaction.
    fn process_file(
        &mut self,
        store: &mut Store,
        path: &Path,
        metadata: &std::fs::Metadata,
        state: &mut PassState<'_>,
        lane: Lane,
        now_ms: i64,
    ) -> Result<FileOutcome, StoreError> {
        if state.cancel_requested() {
            return Ok(FileOutcome::Cancelled);
        }
        let stamp = FileStamp::of(metadata);
        if let Some((processed, outcome)) = state.visited.get(path) {
            return Ok(match *outcome {
                FileOutcome::Done { .. } | FileOutcome::Unchanged if *processed != stamp => {
                    FileOutcome::Done { more: true }
                }
                // The current lane's exhausted reserve must not stop historical siblings.
                FileOutcome::Budget => FileOutcome::Done { more: true },
                outcome => outcome,
            });
        }
        let outcome = self.read_file(store, path, metadata, state, lane, now_ms)?;
        state.visited.insert(path.to_path_buf(), (stamp, outcome));
        Ok(outcome)
    }

    fn read_file(
        &mut self,
        store: &mut Store,
        path: &Path,
        metadata: &std::fs::Metadata,
        state: &mut PassState<'_>,
        lane: Lane,
        now_ms: i64,
    ) -> Result<FileOutcome, StoreError> {
        if state.cancel_requested() {
            return Ok(FileOutcome::Cancelled);
        }
        let Ok(relative) = path.strip_prefix(&self.roots.source) else {
            return Ok(FileOutcome::Failed(FailureCode::RootOverlap));
        };
        let stamp = FileStamp::of(metadata);
        let stored = store.codex_file(&self.source_id, relative)?;
        let same_stamp = |file: &CodexFile| {
            (file.device, file.inode, file.size, file.mtime_ns)
                == (stamp.device, stamp.inode, stamp.size, stamp.mtime_ns)
        };
        let retained_uncovered = stored.as_ref().and_then(|file| file.uncovered);
        let mut file = match stored {
            Some(file)
                if file.present
                    && same_stamp(&file)
                    && (file.byte_offset == file.size
                        || file.tail_state == Some(CodexTailState::Pending)) =>
            {
                return Ok(FileOutcome::Unchanged);
            }
            Some(file) if file.present && same_stamp(&file) => file,
            _ => fresh(relative, stamp),
        };
        file.uncovered = retained_uncovered;
        let allowance = usize::try_from(lane.bytes().saturating_sub(state.counters.bytes_read))
            .unwrap_or(usize::MAX)
            .min(MAX_JSONL_LINE_BYTES);
        if stamp.size > file.byte_offset {
            if allowance == 0 {
                return Ok(FileOutcome::Budget);
            }
            if file.byte_offset == 0 {
                if lane.exhausted(&state.counters) {
                    return Ok(FileOutcome::Budget);
                }
                state.counters.header_reads = state.counters.header_reads.saturating_add(1);
            }
            if let Err(stop) = self.check_identities(&mut state.counters) {
                return Ok(self.root_stop(stop, state));
            }
            state.verified_files = state.files.len();
            let read =
                match self
                    .fs
                    .read_tail(path, file.byte_offset, allowance, &mut state.counters)
                {
                    Ok(read) => read,
                    Err(error) => {
                        if let Err(stop) = self.check_identities(&mut state.counters) {
                            return Ok(self.root_stop(stop, state));
                        }
                        state.verified_files = state.files.len();
                        return Ok(match stop_of(error) {
                            Stop::Budget => FileOutcome::Budget,
                            Stop::ValidationBudget => {
                                self.frontier.validation_budget = true;
                                self.frontier.validation_retry = true;
                                FileOutcome::Budget
                            }
                            Stop::Fail(code) => FileOutcome::Failed(code),
                        });
                    }
                };
            state.counters.bytes_read = state
                .counters
                .bytes_read
                .saturating_add(read.bytes.len() as u64);
            if state.cancel_requested() {
                return Ok(FileOutcome::Cancelled);
            }
            if let Err(stop) = self.check_identities(&mut state.counters) {
                return Ok(self.root_stop(stop, state));
            }
            state.verified_files = state.files.len();
            if read.before != stamp || read.after != read.before {
                return Ok(FileOutcome::Failed(FailureCode::SourceChanging));
            }
            let at_end =
                file.byte_offset.saturating_add(read.bytes.len() as u64) >= read.before.size;
            let full = read.bytes.len() == MAX_JSONL_LINE_BYTES;
            let discarding = file.tail_state == Some(CodexTailState::Discarding);
            let split = jsonl::split(&read.bytes, discarding, at_end, full);
            let mut parse = FileParse::from(&file);
            let mut line_start = file.byte_offset.saturating_add(split.skipped as u64);
            for line in split.lines() {
                #[cfg(feature = "test-faults")]
                LINE_HOOK.with(|slot| {
                    if let Some(hook) = slot.borrow_mut().as_mut() {
                        hook();
                    }
                });
                if state.cancel_requested() {
                    return Ok(FileOutcome::Cancelled);
                }
                if line_start == 0 {
                    file.first_line_fnv64 = jsonl::fnv1a64(line);
                    parse.first_line(line);
                } else {
                    parse.line(line);
                }
                line_start = line_start.saturating_add(line.len() as u64 + 1);
            }
            if split.remainder == Remainder::Oversize {
                parse.uncover(None);
                parse.reject(FailureCode::RecordTooLarge);
                if file.byte_offset == 0 {
                    // The first line was never a readable header: nothing here is admitted.
                    file.first_line_fnv64 = jsonl::fnv1a64(&read.bytes);
                    parse.header_state = Some(CodexHeaderState::ForeignFirstLine);
                    parse.header_era = None;
                    parse.header_id = None;
                }
            }
            file.byte_offset = file.byte_offset.saturating_add(split.consumed as u64);
            file.tail_state = match split.remainder {
                Remainder::Pending => Some(CodexTailState::Pending),
                _ if split.discarding => Some(CodexTailState::Discarding),
                _ => None,
            };
            file.header_id = parse.header_id.take();
            file.header_state = parse.header_state;
            file.header_era = parse.header_era;
            file.record_state = parse.record_state;
            file.uncovered = parse.uncovered;
            (file.device, file.inode, file.size, file.mtime_ns) = (
                read.before.device,
                read.before.inode,
                read.before.size,
                read.before.mtime_ns,
            );
            file.present = true;
            if let Err(stop) = self.check_identities(&mut state.counters) {
                return Ok(self.root_stop(stop, state));
            }
            state.verified_files = state.files.len();
            if state.cancel_requested() {
                return Ok(FileOutcome::Cancelled);
            }
            let changed =
                store.commit_codex_file(&self.source_id, &file, &parse.records, now_ms)?;
            after_file_commit();
            state.records_committed = state.records_committed.saturating_add(changed);
            state.counters.rejected_records = state
                .counters
                .rejected_records
                .saturating_add(parse.rejected);
            if let Some(code) = parse.rejection {
                state.rejection = lesser(state.rejection, code);
            }
            // Bytes left beyond this read (never a pending tail, which waits for its newline).
            return Ok(FileOutcome::Done {
                more: file.byte_offset < file.size
                    && file.tail_state != Some(CodexTailState::Pending),
            });
        }
        // Nothing to read (an empty file, or a stamp change without new bytes): record the stamp.
        (file.device, file.inode, file.size, file.mtime_ns) =
            (stamp.device, stamp.inode, stamp.size, stamp.mtime_ns);
        file.present = true;
        if let Err(stop) = self.check_identities(&mut state.counters) {
            return Ok(self.root_stop(stop, state));
        }
        state.verified_files = state.files.len();
        if state.cancel_requested() {
            return Ok(FileOutcome::Cancelled);
        }
        store.commit_codex_file(&self.source_id, &file, &[], now_ms)?;
        after_file_commit();
        Ok(FileOutcome::Done { more: false })
    }

    fn root_stop(&mut self, stop: Stop, state: &mut PassState<'_>) -> FileOutcome {
        match stop {
            Stop::Budget | Stop::ValidationBudget => {
                self.frontier.validation_budget = true;
                FileOutcome::Budget
            }
            Stop::Fail(code) => {
                state.skip(code);
                FileOutcome::Failed(code)
            }
        }
    }

    fn finish(&mut self, store: &mut Store, state: &mut PassState<'_>, now_ms: i64) -> PassReport {
        if self.frontier.is_drained() && !state.caught_up && !state.cancelled {
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
        let drained = self.frontier.is_drained() && !state.caught_up && !state.cancelled;
        let failure = state
            .skipped
            .filter(|code| *code == FailureCode::RootOverlap)
            .or(state.rejection)
            .or(state.skipped);
        let outcome = if failure == Some(FailureCode::RootOverlap) {
            PassOutcome::Partial
        } else if state.caught_up || state.cancelled {
            PassOutcome::CatchingUp
        } else if failure.is_some() {
            PassOutcome::Partial
        } else {
            PassOutcome::Consistent
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
        let result = store.finish_codex_pass_with_freshness(
            CodexPassRequest {
                source_id: &self.source_id,
                root: &self.roots.source,
                generation: self.generation,
                visited: &state.revalidated,
                files: &state.files,
                frontier: &frontier,
                drained,
                incomplete: state.incomplete,
                outcome,
                failure,
                rejection: state.rejection,
                records_committed: state.records_committed,
                counters: state.counters,
                now_ms,
            },
            !self.frontier.validation_budget,
            retry_files,
        );
        match result {
            Ok(summary) => {
                if summary.completed {
                    self.generation = self.generation.saturating_add(1);
                    self.frontier =
                        DirectoryFrontier::new(&self.roots.source, Vec::new(), Vec::new());
                }
                if failure == Some(FailureCode::RootOverlap) && self.reload(store).is_err() {
                    self.needs_reload = true;
                }
                self.report(store, summary.outcome, summary.failure, state)
            }
            Err(error) => {
                self.needs_reload = true;
                self.report(
                    store,
                    PassOutcome::Partial,
                    Some(store_failure(error)),
                    state,
                )
            }
        }
    }

    fn report(
        &self,
        store: &Store,
        outcome: PassOutcome,
        failure: Option<FailureCode>,
        state: &PassState<'_>,
    ) -> PassReport {
        let last_good_ms = store.last_success_ms(&self.source_id).ok().flatten();
        pass_report(
            outcome,
            failure,
            state.counters,
            state.records_committed,
            last_good_ms,
        )
    }
}

fn fresh(relative: &Path, stamp: FileStamp) -> CodexFile {
    CodexFile {
        relative_path: relative.to_path_buf(),
        device: stamp.device,
        inode: stamp.inode,
        size: stamp.size,
        mtime_ns: stamp.mtime_ns,
        byte_offset: 0,
        first_line_fnv64: 0,
        header_id: None,
        header_state: None,
        header_era: None,
        record_state: CodexRecordState::None,
        tail_state: None,
        uncovered: None,
        present: true,
    }
}

/// `sessions/YYYY/MM/DD` for the UTC dates of `now_ms` and 14 hours either side: every zone's
/// local date of the injected instant is among them.
fn dated_directories(now_ms: i64) -> Vec<PathBuf> {
    let mut directories = Vec::with_capacity(3);
    for offset in [0, -14 * 3_600_000, 14 * 3_600_000] {
        let Some(at) = now_ms
            .checked_add(offset)
            .and_then(|at| jiff::Timestamp::from_millisecond(at).ok())
        else {
            continue;
        };
        let date = at.to_zoned(jiff::tz::TimeZone::UTC).date();
        let directory = PathBuf::from(format!(
            "sessions/{:04}/{:02}/{:02}",
            date.year(),
            date.month(),
            date.day()
        ));
        if !directories.contains(&directory) {
            directories.push(directory);
        }
    }
    directories
}

#[cfg(test)]
mod tests {
    use super::{CodexHeaderEra, era};

    #[test]
    fn era_threshold_is_the_first_record_persisting_release() {
        for (version, expected) in [
            ("0.153.0-alpha.1", CodexHeaderEra::Record),
            ("0.153.0-alpha.0", CodexHeaderEra::Legacy),
            ("0.153.0", CodexHeaderEra::Record),
            ("0.152.99", CodexHeaderEra::Legacy),
            ("0.153.0-alpha.1.0", CodexHeaderEra::Record),
        ] {
            assert_eq!(era(Some(version)), expected, "{version}");
        }
        assert_eq!(era(None), CodexHeaderEra::Legacy);
    }
}
