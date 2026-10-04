#[cfg(feature = "test-faults")]
use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::time::{Duration, Instant};

use rusqlite::types::ValueRef;
use rusqlite::{Connection, Row, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::domain::{
    AcquisitionConsistency, FailureCode, PassCounters, Provenance, RecordCandidate,
    ResolvedCandidate, TokenComponents, resolve_total,
};
use crate::ingest::sqlite_ro::{self, WorkGuard};
use crate::limits::{
    MAX_OPENCODE_RECORD_BYTES, MAX_RECORD_ID_BYTES, MAX_RECORD_ID_COMPONENT_BYTES,
    MAX_SELECTED_PART_IDS, MAX_SOURCE_TIMESTAMP_MS, MAX_SQLITE_TYPE_BYTES, MAX_TOKEN_COUNT,
    SQLITE_MAX_PROGRESS_TICKS, SQLITE_PASS_DEADLINE_MS,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    NotUsage,
    InvalidRecord,
    RecordTooLarge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolveError {
    SourceChanging,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StepFinishPart {
    pub part_id: String,
    pub components: TokenComponents,
    pub explicit_total: Option<u64>,
    pub fingerprint: u64,
}

fn is_valid_record_id_component(value: &str) -> bool {
    crate::domain::is_valid_id_component(value)
}

/// Source timestamps are UTC epoch milliseconds in every layout; values outside the calendar
/// range (negative, or later than year 9999) are rejected, never clamped or rescaled.
pub fn valid_timestamp_ms(value: i64) -> bool {
    (0..=MAX_SOURCE_TIMESTAMP_MS).contains(&value)
        && jiff::Timestamp::from_millisecond(value).is_ok()
}

/// Parent message envelope, validated independently of whether it carries usage.
struct Parent {
    occurred_at_ms: i64,
    eligible: bool,
    usage: Option<(TokenComponents, Option<u64>)>,
    fingerprint: u64,
}

fn parse_parent(
    session_id: &str,
    message_id: &str,
    occurred_at_ms: Option<i64>,
    record_type: Option<&str>,
    payload: &[u8],
) -> Result<Parent, DecodeError> {
    if payload.len() > MAX_OPENCODE_RECORD_BYTES {
        return Err(DecodeError::RecordTooLarge);
    }
    if !is_valid_record_id_component(session_id)
        || !is_valid_record_id_component(message_id)
        || session_id.len().saturating_add(message_id.len()) > MAX_RECORD_ID_BYTES
    {
        return Err(DecodeError::InvalidRecord);
    }
    let occurred_at_ms = occurred_at_ms
        .filter(|timestamp| valid_timestamp_ms(*timestamp))
        .ok_or(DecodeError::InvalidRecord)?;
    let value: Value = serde_json::from_slice(payload).map_err(|_| DecodeError::InvalidRecord)?;
    let object = value.as_object().ok_or(DecodeError::InvalidRecord)?;
    let eligible = match record_type {
        Some(kind) => matches!(kind, "assistant" | "compaction"),
        None => {
            object
                .get("role")
                .and_then(Value::as_str)
                .is_some_and(|role| matches!(role, "assistant" | "model" | "compaction"))
                || object
                    .get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| matches!(kind, "assistant" | "compaction"))
        }
    };
    let fingerprint = fingerprint_extend(
        fingerprint_extend(
            fingerprint_extend(fingerprint(payload), session_id.as_bytes()),
            message_id.as_bytes(),
        ),
        &occurred_at_ms.to_be_bytes(),
    );
    let usage = if eligible {
        match decode_tokens(object) {
            Ok(usage) => Some(usage),
            Err(DecodeError::NotUsage) => None,
            Err(error) => return Err(error),
        }
    } else {
        None
    };
    Ok(Parent {
        occurred_at_ms,
        eligible,
        usage,
        fingerprint,
    })
}

fn candidate_from(
    session_id: &str,
    message_id: &str,
    parent: &Parent,
    usage: (TokenComponents, Option<u64>),
    canonical_path: &Path,
    format_rank: u8,
    acquisition_consistency: AcquisitionConsistency,
) -> RecordCandidate {
    let (total, total_provenance, source_convention) = resolve_total(&usage.0, usage.1);
    RecordCandidate {
        session_id: session_id.to_owned(),
        message_id: message_id.to_owned(),
        occurred_at_ms: parent.occurred_at_ms,
        components: usage.0,
        total,
        total_provenance,
        source_convention,
        acquisition_consistency,
        selected_part_ids: Vec::new(),
        pending_partial: false,
        canonical_path: canonical_path.to_path_buf(),
        format_rank,
        fingerprint: parent.fingerprint,
    }
}

pub fn decode_record(
    session_id: &str,
    message_id: &str,
    occurred_at_ms: Option<i64>,
    record_type: Option<&str>,
    payload: &[u8],
    canonical_path: &Path,
    format_rank: u8,
) -> Result<RecordCandidate, DecodeError> {
    let parent = parse_parent(session_id, message_id, occurred_at_ms, record_type, payload)?;
    let Some(usage) = parent.usage.clone() else {
        return Err(DecodeError::NotUsage);
    };
    Ok(candidate_from(
        session_id,
        message_id,
        &parent,
        usage,
        canonical_path,
        format_rank,
        consistency_of(format_rank),
    ))
}

/// Rank 2 is the JSON layout (read file by file); ranks 0 and 1 are SQLite read transactions.
fn consistency_of(format_rank: u8) -> AcquisitionConsistency {
    if format_rank == 2 {
        AcquisitionConsistency::FileByFileBestEffort
    } else {
        AcquisitionConsistency::SqliteReadTransaction
    }
}

pub fn decode_step_finish_part(
    part_id: &str,
    payload: &[u8],
) -> Result<Option<StepFinishPart>, DecodeError> {
    if payload.len() > MAX_OPENCODE_RECORD_BYTES {
        return Err(DecodeError::RecordTooLarge);
    }
    if !is_valid_record_id_component(part_id) {
        return Err(DecodeError::InvalidRecord);
    }
    let value: Value = serde_json::from_slice(payload).map_err(|_| DecodeError::InvalidRecord)?;
    let object = value.as_object().ok_or(DecodeError::InvalidRecord)?;
    if object.get("type").and_then(Value::as_str) != Some("step-finish") {
        return Ok(None);
    }
    let (components, explicit_total) = decode_tokens(object).map_err(|error| {
        if error == DecodeError::NotUsage {
            DecodeError::InvalidRecord
        } else {
            error
        }
    })?;
    Ok(Some(StepFinishPart {
        part_id: part_id.to_owned(),
        components,
        explicit_total,
        fingerprint: fingerprint(payload),
    }))
}

/// One message and the step-finish parts read for it.
pub struct GroupInput<'a> {
    pub session_id: &'a str,
    pub message_id: &'a str,
    pub occurred_at_ms: Option<i64>,
    pub record_type: Option<&'a str>,
    pub message_payload: &'a [u8],
    pub parts: &'a [StepFinishPart],
    /// Some part could not be read or decoded; the prior complete group stays pending.
    pub incomplete: bool,
    pub canonical_path: &'a Path,
    pub format_rank: u8,
}

/// Builds one message group: a valid usage-bearing parent alone, or completed step-finish parts
/// that replace the parent's own counters. The parent envelope (identity, time, role) is
/// validated whether or not the parent itself carries usage.
pub fn assemble_group(input: &GroupInput<'_>) -> Result<Option<RecordCandidate>, DecodeError> {
    let parent = parse_parent(
        input.session_id,
        input.message_id,
        input.occurred_at_ms,
        input.record_type,
        input.message_payload,
    )?;
    if !parent.eligible {
        return Ok(None);
    }
    let own = parent.usage.clone();
    if !input.parts.is_empty() {
        let base = candidate_from(
            input.session_id,
            input.message_id,
            &parent,
            own.unwrap_or_default(),
            input.canonical_path,
            input.format_rank,
            consistency_of(input.format_rank),
        );
        let mut group = replace_parent_with_parts(&base, input.parts)?;
        group.pending_partial = input.incomplete;
        return Ok(Some(group));
    }
    if let Some(usage) = own {
        let mut candidate = candidate_from(
            input.session_id,
            input.message_id,
            &parent,
            usage,
            input.canonical_path,
            input.format_rank,
            consistency_of(input.format_rank),
        );
        candidate.pending_partial = input.incomplete;
        return Ok(Some(candidate));
    }
    if input.incomplete {
        return Err(DecodeError::InvalidRecord);
    }
    Ok(None)
}

/// Builds the group of one JSON message from the step-finish parts already decoded for it.
pub fn decode_json_group(
    session_id: &str,
    message_id: &str,
    message_payload: &[u8],
    parts: &[StepFinishPart],
    incomplete: bool,
    canonical_path: &Path,
) -> Result<Option<RecordCandidate>, DecodeError> {
    if message_payload.len() > MAX_OPENCODE_RECORD_BYTES {
        return Err(DecodeError::RecordTooLarge);
    }
    let value: Value =
        serde_json::from_slice(message_payload).map_err(|_| DecodeError::InvalidRecord)?;
    let object = value.as_object().ok_or(DecodeError::InvalidRecord)?;
    let timestamp = json_timestamp(object).ok_or(DecodeError::InvalidRecord)?;
    assemble_group(&GroupInput {
        session_id,
        message_id,
        occurred_at_ms: Some(timestamp),
        record_type: None,
        message_payload,
        parts,
        incomplete,
        canonical_path,
        format_rank: 2,
    })
}

fn json_timestamp(object: &serde_json::Map<String, Value>) -> Option<i64> {
    let created = object.get("time")?.as_object()?.get("created")?.as_u64()?;
    i64::try_from(created)
        .ok()
        .filter(|value| valid_timestamp_ms(*value))
}

/// Replaces a parent's counters with the sum of its completed parts.
///
/// Each part contributes an explicit total or, when it has all five components, the pinned
/// derived total; the group total exists only when every part resolves one. Every summed
/// component and the total are checked against the normative numeric ceiling before the group
/// can be staged or published, so an explicit total never waives a component limit.
pub fn replace_parent_with_parts(
    parent: &RecordCandidate,
    parts: &[StepFinishPart],
) -> Result<RecordCandidate, DecodeError> {
    if parts.is_empty() || parts.len() > MAX_SELECTED_PART_IDS {
        return Err(DecodeError::InvalidRecord);
    }
    let mut selected_part_ids = parts
        .iter()
        .map(|part| part.part_id.clone())
        .collect::<Vec<_>>();
    selected_part_ids.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    if selected_part_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(DecodeError::InvalidRecord);
    }

    let components = TokenComponents {
        input: sum_component(parts.iter().map(|part| part.components.input))?,
        output: sum_component(parts.iter().map(|part| part.components.output))?,
        reasoning: sum_component(parts.iter().map(|part| part.components.reasoning))?,
        cache_read: sum_component(parts.iter().map(|part| part.components.cache_read))?,
        cache_write: sum_component(parts.iter().map(|part| part.components.cache_write))?,
    };
    // Each part resolves to an explicit (reported) or permitted derived total; the group total
    // exists only when every part resolves one, and is derived if any part is.
    let mut total = Some(0_u64);
    let mut any_derived = false;
    for part in parts {
        let (part_total, provenance, _) = resolve_total(&part.components, part.explicit_total);
        any_derived |= provenance == Some(Provenance::Derived);
        total = match (total, part_total) {
            (Some(sum), Some(part_total)) => Some(
                sum.checked_add(part_total)
                    .ok_or(DecodeError::InvalidRecord)?,
            ),
            _ => None,
        };
    }
    if total.is_some_and(|total| total > MAX_TOKEN_COUNT) {
        return Err(DecodeError::InvalidRecord);
    }
    validate_component_range(&components)?;
    let mut candidate = parent.clone();
    candidate.components = components;
    candidate.total = total;
    candidate.total_provenance = total.map(|_| {
        if any_derived {
            Provenance::Derived
        } else {
            Provenance::Reported
        }
    });
    candidate.source_convention = total
        .filter(|_| any_derived)
        .map(|_| crate::domain::OPENCODE_SOURCE_CONVENTION.to_owned());
    candidate.selected_part_ids = selected_part_ids;
    candidate.pending_partial = false;
    candidate.fingerprint = parts.iter().fold(parent.fingerprint, |hash, part| {
        fingerprint_extend(
            fingerprint_extend(hash, part.part_id.as_bytes()),
            &part.fingerprint.to_be_bytes(),
        )
    });
    Ok(candidate)
}

/// Every component of a record, summed or not, must stay inside the normative ceiling.
pub fn validate_component_range(components: &TokenComponents) -> Result<(), DecodeError> {
    let within = [
        components.input,
        components.output,
        components.reasoning,
        components.cache_read,
        components.cache_write,
    ]
    .into_iter()
    .flatten()
    .all(|value| value <= MAX_TOKEN_COUNT);
    if within {
        Ok(())
    } else {
        Err(DecodeError::InvalidRecord)
    }
}

/// A message group whose part rows span passes: the parent it belongs to, the last raw part id
/// consumed and the step-finish parts decoded so far. Bounded by `MAX_SELECTED_PART_IDS`.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct GroupCursor {
    rowid: i64,
    parent_fingerprint: u64,
    after_part: Option<String>,
    parts: Vec<StepFinishPart>,
    incomplete: bool,
    /// Snapshot witness of the transaction that began this group: the group may only resume,
    /// across transactions, while the database has seen no commit since. Absent or unstable
    /// witnesses never resume, so a cached part is never mixed with newer source data.
    #[serde(default)]
    witness: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct TableCursor {
    /// Last completed message rowid; `None` means no lower bound (every rowid is reachable).
    rowid: Option<i64>,
    done: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    group: Option<GroupCursor>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct DatabaseCursor {
    legacy: TableCursor,
    v2: TableCursor,
}

impl DatabaseCursor {
    /// A decoded cursor must stay within the bounds its producer guarantees and describe a state
    /// the producer can reach: a completed table holds no suspended group, a suspended group lies
    /// after the last completed rowid and carries ordered, bounded, unique parts.
    fn validate(&self) -> Result<(), FailureCode> {
        for table in [&self.legacy, &self.v2] {
            let Some(group) = &table.group else {
                continue;
            };
            let ordered = group
                .parts
                .windows(2)
                .all(|pair| pair[0].part_id.as_bytes() < pair[1].part_id.as_bytes());
            let within = group.after_part.as_ref().is_some_and(|after| {
                group
                    .parts
                    .iter()
                    .all(|part| part.part_id.as_bytes() <= after.as_bytes())
            });
            if table.done
                || group.parts.len() > MAX_SELECTED_PART_IDS
                || group.after_part.as_ref().is_none_or(|id| {
                    !is_valid_record_id_component(id) || id.len() > MAX_RECORD_ID_COMPONENT_BYTES
                })
                || group
                    .parts
                    .iter()
                    .any(|part| !is_valid_record_id_component(&part.part_id))
                || !ordered
                || !within
                || table.rowid.is_some_and(|rowid| group.rowid <= rowid)
            {
                return Err(FailureCode::Store);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqliteBatch {
    pub records: Vec<RecordCandidate>,
    pub cursor_key: Option<String>,
    pub failure: Option<FailureCode>,
    pub complete_sweep: bool,
}

/// Absolute ceilings on the pass counters for one source read; the engine lowers them for the
/// reserved current-file lane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadBudget {
    pub rows: u32,
    pub bytes: u64,
}

pub fn cursor_is_complete(cursor_key: Option<&str>) -> Result<bool, FailureCode> {
    let Some(cursor_key) = cursor_key else {
        return Ok(false);
    };
    let cursor: DatabaseCursor =
        serde_json::from_str(cursor_key).map_err(|_| FailureCode::Store)?;
    cursor.validate()?;
    Ok(cursor.legacy.done && cursor.v2.done)
}

const MESSAGE_COLUMNS: &[&str] = &["id", "session_id", "time_created", "data"];
const PART_COLUMNS: &[&str] = &["id", "message_id", "session_id", "data"];
const V2_COLUMNS: &[&str] = &["id", "session_id", "type", "seq", "time_created", "data"];

/// Where a message sweep starts: no lower bound at all, after a completed rowid, or at the
/// rowid of a group that was suspended mid-way.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lower {
    Start,
    After,
    From,
}

/// Messages in rowid order. Identity, type and payload columns are guarded in SQL by
/// `typeof`/`octet_length`, so an oversized, mistyped or unaffordable value is never copied out
/// of SQLite, and the cursor is a bounded rowid rather than attacker-sized text.
///
/// Parameters: `?1` identity bytes, `?2` record bytes, `?3` row limit, `?4` type bytes, `?5`
/// bytes still allowed this pass, `?6` the lower rowid for [`Lower::After`]/[`Lower::From`].
fn message_sql(table: &str, has_type: bool, lower: Lower) -> String {
    // Whether any part of this message has an identity that cannot be a keyset position: one
    // column of the parent row (no extra row), guarded so an oversized parent identity is never
    // used as a key. Identities that fail it never reach the part sorter or result set.
    let unsafe_parts = if table == "message" {
        "CASE WHEN typeof(session_id) = 'text' AND octet_length(session_id) <= ?1 \
              AND typeof(id) = 'text' AND octet_length(id) <= ?1 \
         THEN EXISTS(SELECT 1 FROM part WHERE part.message_id = message.id \
              AND part.session_id = message.session_id \
              AND (typeof(part.id) <> 'text' OR octet_length(part.id) > ?1)) \
         ELSE 0 END"
    } else {
        "0"
    };
    let (type_columns, type_ok) = if has_type {
        (
            ", typeof(type), octet_length(type), \
             CASE WHEN typeof(type) = 'text' AND octet_length(type) <= ?4 THEN type END",
            " AND typeof(type) = 'text' AND octet_length(type) <= ?4",
        )
    } else {
        (", NULL, NULL, NULL", "")
    };
    let condition = match lower {
        Lower::Start => "1",
        Lower::After => "rowid > ?6",
        Lower::From => "rowid >= ?6",
    };
    format!(
        "SELECT rowid, time_created, \
         typeof(session_id), octet_length(session_id), \
         CASE WHEN typeof(session_id) = 'text' AND octet_length(session_id) <= ?1 THEN session_id END, \
         typeof(id), octet_length(id), \
         CASE WHEN typeof(id) = 'text' AND octet_length(id) <= ?1 THEN id END, \
         typeof(data), octet_length(data), \
         CASE WHEN typeof(session_id) = 'text' AND octet_length(session_id) <= ?1 \
                   AND typeof(id) = 'text' AND octet_length(id) <= ?1{type_ok} \
                   AND typeof(data) IN ('text', 'blob') \
                   AND octet_length(data) <= ?2 AND octet_length(data) <= ?5 THEN data END\
         {type_columns}, {unsafe_parts} \
         FROM {table} WHERE {condition} ORDER BY rowid LIMIT ?3"
    )
}

/// Part ids and sizes only (small sorter rows); payloads are fetched one at a time afterwards.
/// `?1` message, `?2` session, `?3` identity bytes, `?4` row limit.
pub const PART_LIST_SQL: &str = "SELECT typeof(id), octet_length(id), \
     CASE WHEN typeof(id) = 'text' AND octet_length(id) <= ?3 THEN id END, \
     typeof(data), octet_length(data) \
     FROM part WHERE message_id = ?1 AND session_id = ?2 \
       AND typeof(id) = 'text' AND octet_length(id) <= ?3 ORDER BY id LIMIT ?4";

/// Continuation of [`PART_LIST_SQL`] after the part id `?5`.
pub const PART_LIST_AFTER_SQL: &str = "SELECT typeof(id), octet_length(id), \
     CASE WHEN typeof(id) = 'text' AND octet_length(id) <= ?3 THEN id END, \
     typeof(data), octet_length(data) \
     FROM part WHERE message_id = ?1 AND session_id = ?2 AND id > ?5 \
       AND typeof(id) = 'text' AND octet_length(id) <= ?3 ORDER BY id LIMIT ?4";

pub const PART_PAYLOAD_SQL: &str = "SELECT \
     CASE WHEN typeof(data) IN ('text', 'blob') AND octet_length(data) <= ?3 THEN data END \
     FROM part WHERE id = ?1 AND message_id = ?2 LIMIT 1";

/// Message query text for a layout, exposed so tests can inspect its plan and work.
pub fn message_query(v2: bool, lower: Lower) -> String {
    if v2 {
        message_sql("session_message", true, lower)
    } else {
        message_sql("message", false, lower)
    }
}

#[cfg(feature = "test-faults")]
thread_local! {
    static TRANSACTION_HOOK: RefCell<Option<Box<dyn FnMut()>>> = const { RefCell::new(None) };
    static PROGRESS_TICKS: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// Test boundary: runs `hook` once inside the next source read transaction, after its first
/// completed group, so a test can commit a concurrent writer change while the snapshot is open.
#[cfg(feature = "test-faults")]
pub fn set_transaction_hook(hook: Option<Box<dyn FnMut()>>) {
    TRANSACTION_HOOK.with(|slot| *slot.borrow_mut() = hook);
}

/// Test boundary: replaces the SQLite progress-callback allowance of every source read on this
/// thread, so work interruption is driven by deterministic VM work instead of wall time.
#[cfg(feature = "test-faults")]
pub fn set_progress_ticks(ticks: Option<u64>) {
    PROGRESS_TICKS.with(|slot| slot.set(ticks));
}

fn progress_ticks() -> u64 {
    #[cfg(feature = "test-faults")]
    if let Some(ticks) = PROGRESS_TICKS.with(std::cell::Cell::get) {
        return ticks;
    }
    SQLITE_MAX_PROGRESS_TICKS
}

fn run_transaction_hook() {
    #[cfg(feature = "test-faults")]
    {
        let hook = TRANSACTION_HOOK.with(|slot| slot.borrow_mut().take());
        if let Some(mut hook) = hook {
            hook();
        }
    }
}

/// Text column after the SQL-side type and size guard; `None` when it was withheld or invalid.
fn guarded_text(row: &Row<'_>, first: usize, limit: usize) -> rusqlite::Result<Option<String>> {
    let kind: Option<String> = row.get(first)?;
    let length: Option<i64> = row.get(first + 1)?;
    let within = kind.as_deref() == Some("text")
        && length.is_some_and(|length| length >= 0 && length as u64 <= limit as u64);
    if !within {
        return Ok(None);
    }
    Ok(match row.get_ref(first + 2)? {
        ValueRef::Text(bytes) => std::str::from_utf8(bytes).ok().map(str::to_owned),
        _ => None,
    })
}

enum Payload {
    Bytes(Vec<u8>),
    TooLarge,
    Invalid,
    /// Valid, but it would cross the pass byte allowance; not copied.
    NoBudget,
}

/// Owns the payload bytes only after kind, size and the remaining pass allowance are proven.
fn guarded_payload(
    kind: Option<&str>,
    length: Option<i64>,
    value: ValueRef<'_>,
    remaining: u64,
) -> Payload {
    match (kind, length) {
        (Some("text" | "blob"), Some(length)) if length >= 0 => {
            let length = length as u64;
            if length > MAX_OPENCODE_RECORD_BYTES as u64 {
                return Payload::TooLarge;
            }
            if length > remaining {
                return Payload::NoBudget;
            }
            match value {
                ValueRef::Text(bytes) | ValueRef::Blob(bytes) => Payload::Bytes(bytes.to_vec()),
                _ => Payload::Invalid,
            }
        }
        _ => Payload::Invalid,
    }
}

struct Unit {
    rowid: i64,
    session_id: Option<String>,
    message_id: Option<String>,
    record_type: Option<String>,
    type_ok: bool,
    occurred_at_ms: Option<i64>,
    payload: Payload,
    unsafe_parts: bool,
}

fn read_unit(row: &Row<'_>, has_type: bool, remaining: u64) -> rusqlite::Result<Unit> {
    let occurred_at_ms = match row.get_ref(1)? {
        ValueRef::Integer(value) => Some(value),
        _ => None,
    };
    let data_kind: Option<String> = row.get(8)?;
    let data_len: Option<i64> = row.get(9)?;
    let (record_type, type_ok) = if has_type {
        let value = guarded_text(row, 11, MAX_SQLITE_TYPE_BYTES)?;
        let ok = value.is_some();
        (value, ok)
    } else {
        (None, true)
    };
    Ok(Unit {
        rowid: row.get(0)?,
        session_id: guarded_text(row, 2, MAX_RECORD_ID_COMPONENT_BYTES)?,
        message_id: guarded_text(row, 5, MAX_RECORD_ID_COMPONENT_BYTES)?,
        record_type,
        type_ok,
        occurred_at_ms,
        payload: guarded_payload(data_kind.as_deref(), data_len, row.get_ref(10)?, remaining),
        unsafe_parts: row.get::<_, i64>(14)? != 0,
    })
}

struct Sweep<'a, 'c> {
    transaction: &'a Transaction<'c>,
    canonical_path: &'a Path,
    counters: &'a mut PassCounters,
    budget: ReadBudget,
    started: Instant,
    records: Vec<RecordCandidate>,
    failure: Option<FailureCode>,
    hooked: bool,
    witness: Option<u64>,
}

impl Sweep<'_, '_> {
    fn out_of_time(&self) -> bool {
        self.started.elapsed() >= Duration::from_millis(SQLITE_PASS_DEADLINE_MS)
    }

    fn reject(&mut self, code: FailureCode) {
        self.counters.rejected_records = self.counters.rejected_records.saturating_add(1);
        self.failure = Some(code);
    }

    fn rows_left(&self) -> u32 {
        self.budget.rows.saturating_sub(self.counters.rows_read)
    }

    fn bytes_left(&self) -> u64 {
        self.budget.bytes.saturating_sub(self.counters.bytes_read)
    }

    /// Charges rows physically emitted by SQLite. Counters only grow within a pass, whether or
    /// not the group they belong to is later published.
    fn charge_rows(&mut self, rows: u32) {
        self.counters.rows_read = self.counters.rows_read.saturating_add(rows);
    }

    fn after_unit(&mut self) {
        if !self.hooked {
            self.hooked = true;
            run_transaction_hook();
        }
    }
}

enum UnitOutcome {
    Done,
    /// Nothing more fits this pass; the unit is retried whole.
    NoBudget,
    /// The group's part rows span passes; resume from this state.
    Suspended(GroupCursor),
}

/// Reads whole message groups in rowid order until the table ends or a budget would be crossed.
/// Rows and bytes are reserved before SQLite is asked for the next row; a group whose parts do
/// not all fit is suspended with a bounded cursor, so a group of any size drains across passes.
fn sweep_table(
    sweep: &mut Sweep<'_, '_>,
    statements: &mut Option<Statements<'_>>,
    table: &str,
    v2: bool,
    mut cursor: TableCursor,
) -> Result<TableCursor, FailureCode> {
    if cursor.done {
        return Ok(cursor);
    }
    let mut seen = 0_u32;
    let mut stopped = false;
    let mut timed_out = false;
    let mut exhausted = false;
    let transaction = sweep.transaction;
    'statements: loop {
        // Whatever SQLite emits for one statement is reserved up front: at most as many rows as the
        // remaining byte allowance can hold at the per-record ceiling, so the producer never emits
        // more payload than the pass may still read. A statement that ends at that limit is followed
        // by another from the last completed group, with the budget that is left.
        let affordable = (sweep.bytes_left() / MAX_OPENCODE_RECORD_BYTES as u64).max(1);
        let limit = sweep
            .rows_left()
            .min(u32::try_from(affordable).unwrap_or(u32::MAX));
        if limit == 0 {
            stopped = true;
            break 'statements;
        }
        let (lower, lower_rowid) = match (&cursor.group, cursor.rowid) {
            (Some(group), _) => (Lower::From, Some(group.rowid)),
            (None, Some(rowid)) => (Lower::After, Some(rowid)),
            (None, None) => (Lower::Start, None),
        };
        let sql = message_sql(table, v2, lower);
        let mut statement = transaction.prepare(&sql).map_err(sqlite_failure)?;
        let mut parameters = vec![
            MAX_RECORD_ID_COMPONENT_BYTES as i64,
            MAX_OPENCODE_RECORD_BYTES as i64,
            i64::from(limit),
            MAX_SQLITE_TYPE_BYTES as i64,
            i64::try_from(sweep.bytes_left()).unwrap_or(i64::MAX),
        ];
        parameters.extend(lower_rowid);
        let mut rows = statement
            .query(rusqlite::params_from_iter(parameters))
            .map_err(sqlite_failure)?;
        let mut emitted = 0_u32;
        loop {
            if sweep.rows_left() == 0 {
                stopped = true;
                break;
            }
            if sweep.out_of_time() {
                stopped = true;
                timed_out = true;
                break;
            }
            let row = match rows.next() {
                Ok(Some(row)) => row,
                Ok(None) => {
                    exhausted = true;
                    break;
                }
                Err(error) => match sqlite_failure(error) {
                    FailureCode::LimitExceeded => {
                        stopped = true;
                        timed_out = true;
                        break;
                    }
                    code => return Err(code),
                },
            };
            sweep.charge_rows(1);
            emitted += 1;
            let unit = read_unit(row, v2, sweep.bytes_left()).map_err(sqlite_failure)?;
            let resume = cursor
                .group
                .take()
                .filter(|group| group.rowid == unit.rowid);
            let outcome = match process_unit(sweep, statements, &unit, v2, resume) {
                Ok(outcome) => outcome,
                // The work limit interrupted this group's own queries: it is retried whole.
                Err(FailureCode::LimitExceeded) => {
                    stopped = true;
                    timed_out = true;
                    break;
                }
                Err(code) => return Err(code),
            };
            match outcome {
                UnitOutcome::Done => {
                    cursor.rowid = Some(unit.rowid);
                    cursor.group = None;
                    seen += 1;
                    sweep.after_unit();
                }
                UnitOutcome::NoBudget => {
                    stopped = true;
                    break;
                }
                UnitOutcome::Suspended(group) => {
                    cursor.group = Some(group);
                    stopped = true;
                    break;
                }
            }
        }
        if exhausted && emitted == limit && !stopped {
            exhausted = false;
            continue 'statements;
        }
        break 'statements;
    }
    if timed_out && seen == 0 && cursor.group.is_none() {
        // Not even one group fits the work limit: say so instead of silently never advancing.
        return Err(FailureCode::LimitExceeded);
    }
    cursor.done = exhausted && !stopped;
    Ok(cursor)
}

fn process_unit(
    sweep: &mut Sweep<'_, '_>,
    statements: &mut Option<Statements<'_>>,
    unit: &Unit,
    v2: bool,
    resume: Option<GroupCursor>,
) -> Result<UnitOutcome, FailureCode> {
    let (Some(session_id), Some(message_id)) = (&unit.session_id, &unit.message_id) else {
        sweep.reject(FailureCode::InvalidRecord);
        return Ok(UnitOutcome::Done);
    };
    if v2 && !unit.type_ok {
        sweep.reject(FailureCode::InvalidRecord);
        return Ok(UnitOutcome::Done);
    }
    let payload = match &unit.payload {
        Payload::Bytes(bytes) => bytes,
        Payload::TooLarge => {
            sweep.reject(FailureCode::RecordTooLarge);
            return Ok(UnitOutcome::Done);
        }
        Payload::Invalid => {
            sweep.reject(FailureCode::InvalidRecord);
            return Ok(UnitOutcome::Done);
        }
        Payload::NoBudget => return Ok(UnitOutcome::NoBudget),
    };
    let format_rank = u8::from(v2);
    let parent_bytes = payload.len() as u64;
    sweep.counters.bytes_read = sweep.counters.bytes_read.saturating_add(parent_bytes);
    let parent_fingerprint = fingerprint(payload);

    let mut parts = Vec::new();
    let mut incomplete = false;
    if !v2 {
        let Some(statements) = statements.as_mut() else {
            return Err(FailureCode::UnsupportedSchema);
        };
        if unit.unsafe_parts {
            // An identity that cannot address a keyset position: the group is incomplete and
            // never lists its parts (no oversized key reaches the sorter).
            sweep.reject(FailureCode::InvalidRecord);
            incomplete = true;
        } else {
            // A suspended group resumes only while its parent row is byte-identical.
            let resume = resume.filter(|group| {
                group.parent_fingerprint == parent_fingerprint
                    && group.witness.is_some()
                    && group.witness == sweep.witness
            });
            match read_parts(
                sweep,
                statements,
                session_id,
                message_id,
                (unit.rowid, parent_fingerprint),
                resume,
            )? {
                PartRead::Complete {
                    parts: read,
                    incomplete: partial,
                } => {
                    parts = read;
                    incomplete = partial;
                }
                PartRead::NoBudget => return Ok(UnitOutcome::NoBudget),
                PartRead::Suspended(group) => return Ok(UnitOutcome::Suspended(group)),
                PartRead::Rejected(code) => {
                    // The group can never be read: flag any prior complete group as pending.
                    sweep.reject(code);
                    let stub = pending_stub(
                        session_id,
                        message_id,
                        unit.occurred_at_ms,
                        payload,
                        sweep.canonical_path,
                        format_rank,
                    );
                    sweep.records.extend(stub);
                    return Ok(UnitOutcome::Done);
                }
            }
        }
    }
    match assemble_group(&GroupInput {
        session_id,
        message_id,
        occurred_at_ms: unit.occurred_at_ms,
        record_type: unit.record_type.as_deref(),
        message_payload: payload,
        parts: &parts,
        incomplete,
        canonical_path: sweep.canonical_path,
        format_rank,
    }) {
        Ok(Some(candidate)) => {
            if candidate.pending_partial {
                sweep.failure = Some(FailureCode::InvalidRecord);
            }
            sweep.records.push(candidate);
        }
        Ok(None) | Err(DecodeError::NotUsage) => {}
        Err(error) => sweep.reject(match error {
            DecodeError::RecordTooLarge => FailureCode::RecordTooLarge,
            _ => FailureCode::InvalidRecord,
        }),
    }
    Ok(UnitOutcome::Done)
}

/// A pending marker for a group that could not be read: it never publishes numbers, only flags
/// the prior complete group as incomplete.
fn pending_stub(
    session_id: &str,
    message_id: &str,
    occurred_at_ms: Option<i64>,
    payload: &[u8],
    path: &Path,
    format_rank: u8,
) -> Option<RecordCandidate> {
    let parent = parse_parent(session_id, message_id, occurred_at_ms, None, payload).ok()?;
    let mut candidate = candidate_from(
        session_id,
        message_id,
        &parent,
        (TokenComponents::default(), None),
        path,
        format_rank,
        consistency_of(format_rank),
    );
    candidate.pending_partial = true;
    Some(candidate)
}

enum PartRead {
    Complete {
        parts: Vec<StepFinishPart>,
        incomplete: bool,
    },
    NoBudget,
    Suspended(GroupCursor),
    Rejected(FailureCode),
}

struct PartEntry {
    id: Option<String>,
    length: u64,
    typed: bool,
}

/// Statements prepared once per read and reused for every group.
struct Statements<'a> {
    list_first: rusqlite::Statement<'a>,
    list_after: rusqlite::Statement<'a>,
    payload: rusqlite::Statement<'a>,
}

/// Reads one message's raw part rows incrementally: each list row and each payload fetch is
/// reserved against the shared row allowance before SQLite emits it. Only decoded step-finish
/// parts are kept (at most `MAX_SELECTED_PART_IDS`); any number of raw non-usage parts traverse
/// the budget and resume across passes.
fn read_parts(
    sweep: &mut Sweep<'_, '_>,
    statements: &mut Statements<'_>,
    session_id: &str,
    message_id: &str,
    (rowid, parent_fingerprint): (i64, u64),
    resume: Option<GroupCursor>,
) -> Result<PartRead, FailureCode> {
    let (mut parts, mut incomplete, mut after) = match resume {
        Some(group) => (group.parts, group.incomplete, group.after_part),
        None => (Vec::new(), false, None),
    };
    let started_after = after.clone();
    let witness = sweep.witness;
    let suspend = |parts: Vec<StepFinishPart>, incomplete: bool, after: Option<String>| {
        if after == started_after {
            PartRead::NoBudget
        } else {
            PartRead::Suspended(GroupCursor {
                rowid,
                parent_fingerprint,
                after_part: after,
                parts,
                incomplete,
                witness,
            })
        }
    };
    loop {
        let left = sweep.rows_left();
        if left == 0 {
            return Ok(suspend(parts, incomplete, after));
        }
        // Every listed part may need one payload row, so reserve two rows per part (one row
        // still lists, so a group without parts costs nothing beyond its parent).
        let limit = i64::from((left / 2).max(1));
        let mut entries = Vec::new();
        {
            let statement = if after.is_some() {
                &mut statements.list_after
            } else {
                &mut statements.list_first
            };
            let mut parameters: Vec<&dyn rusqlite::ToSql> = vec![
                &message_id,
                &session_id,
                &(MAX_RECORD_ID_COMPONENT_BYTES as i64),
                &limit,
            ];
            if let Some(id) = &after {
                parameters.push(id);
            }
            let mut rows = statement
                .query(parameters.as_slice())
                .map_err(sqlite_failure)?;
            while let Some(row) = rows.next().map_err(sqlite_failure)? {
                let id =
                    guarded_text(row, 0, MAX_RECORD_ID_COMPONENT_BYTES).map_err(sqlite_failure)?;
                let kind: Option<String> = row.get(3).map_err(sqlite_failure)?;
                let length: Option<i64> = row.get(4).map_err(sqlite_failure)?;
                entries.push(PartEntry {
                    id,
                    length: length.unwrap_or(0).max(0) as u64,
                    typed: matches!(kind.as_deref(), Some("text" | "blob"))
                        && length.is_some_and(|length| length >= 0),
                });
            }
        }
        let listed = entries.len();
        sweep.charge_rows(u32::try_from(listed).unwrap_or(u32::MAX));
        for entry in entries {
            let Some(part_id) = entry.id else {
                // A part id that cannot address a keyset position ends the traversal: the group
                // is flagged incomplete and its prior complete group stays pending.
                sweep.reject(FailureCode::InvalidRecord);
                return Ok(PartRead::Complete {
                    parts,
                    incomplete: true,
                });
            };
            if !entry.typed {
                sweep.reject(FailureCode::InvalidRecord);
                incomplete = true;
                after = Some(part_id);
                continue;
            }
            if entry.length > MAX_OPENCODE_RECORD_BYTES as u64 {
                sweep.reject(FailureCode::RecordTooLarge);
                incomplete = true;
                after = Some(part_id);
                continue;
            }
            if entry.length > sweep.bytes_left() {
                // Not affordable this pass: keep everything before this part.
                return Ok(suspend(parts, incomplete, after));
            }
            if sweep.rows_left() == 0 {
                // The payload row cannot be afforded: keep everything before this part.
                return Ok(suspend(parts, incomplete, after));
            }
            sweep.charge_rows(1);
            let payload: Option<Vec<u8>> = statements
                .payload
                .query_row(
                    params![part_id, message_id, MAX_OPENCODE_RECORD_BYTES as i64],
                    |row| {
                        Ok(match row.get_ref(0)? {
                            ValueRef::Text(bytes) | ValueRef::Blob(bytes) => Some(bytes.to_vec()),
                            _ => None,
                        })
                    },
                )
                .map_err(sqlite_failure)?;
            let Some(payload) = payload else {
                sweep.reject(FailureCode::InvalidRecord);
                incomplete = true;
                after = Some(part_id);
                continue;
            };
            sweep.counters.bytes_read = sweep
                .counters
                .bytes_read
                .saturating_add(payload.len() as u64);
            match decode_step_finish_part(&part_id, &payload) {
                Ok(Some(part)) => parts.push(part),
                Ok(None) => {}
                Err(error) => {
                    incomplete = true;
                    sweep.reject(match error {
                        DecodeError::RecordTooLarge => FailureCode::RecordTooLarge,
                        _ => FailureCode::InvalidRecord,
                    });
                }
            }
            if parts.len() > MAX_SELECTED_PART_IDS {
                return Ok(PartRead::Rejected(FailureCode::LimitExceeded));
            }
            after = Some(part_id);
        }
        if (listed as i64) < limit {
            return Ok(PartRead::Complete { parts, incomplete });
        }
    }
}

/// Reads one bounded slice of the database inside a single read transaction.
///
/// Row, byte and time budgets are shared by parents and their parts. Complete groups are
/// returned with a rowid cursor positioned after the last complete group, so a group that does
/// not fit is retried whole (or resumed, when it spans passes) and a source larger than one pass
/// still drains.
pub fn read_sqlite(
    connection: &mut Connection,
    canonical_path: &Path,
    cursor_key: Option<&str>,
    counters: &mut PassCounters,
    budget: ReadBudget,
) -> Result<SqliteBatch, FailureCode> {
    let mut cursor = match cursor_key {
        Some(json) => {
            let cursor =
                serde_json::from_str::<DatabaseCursor>(json).map_err(|_| FailureCode::Store)?;
            cursor.validate()?;
            cursor
        }
        None => DatabaseCursor::default(),
    };
    // Schema admission emits rows too: they are reserved against the same producer allowance
    // before the first one is read. A pass with too little left reads nothing and retries.
    if budget.rows.saturating_sub(counters.rows_read) < ADMISSION_ROWS_RESERVE {
        return Ok(SqliteBatch {
            records: Vec::new(),
            cursor_key: cursor_key.map(str::to_owned),
            failure: None,
            complete_sweep: false,
        });
    }
    let witness_before = sqlite_ro::snapshot_witness(canonical_path).ok();
    let work = WorkGuard::begin(
        Duration::from_millis(SQLITE_PASS_DEADLINE_MS),
        progress_ticks(),
    );
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(sqlite_failure)?;
    let mut admission_rows = 0_u32;
    let layouts = validate_layouts(&transaction, &mut admission_rows)?;
    counters.rows_read = counters.rows_read.saturating_add(admission_rows);
    // The snapshot is only trusted as one witnessed state if no commit landed between the
    // witness taken before it and the one taken after its first read.
    let witness = match (
        witness_before,
        sqlite_ro::snapshot_witness(canonical_path).ok(),
    ) {
        (Some(before), Some(after)) if before == after => Some(before),
        _ => None,
    };
    cursor.legacy.done |= !layouts.legacy;
    cursor.v2.done |= !layouts.v2;
    let mut statements = if layouts.legacy {
        Some(Statements {
            list_first: transaction.prepare(PART_LIST_SQL).map_err(sqlite_failure)?,
            list_after: transaction
                .prepare(PART_LIST_AFTER_SQL)
                .map_err(sqlite_failure)?,
            payload: transaction
                .prepare(PART_PAYLOAD_SQL)
                .map_err(sqlite_failure)?,
        })
    } else {
        None
    };
    let mut sweep = Sweep {
        transaction: &transaction,
        canonical_path,
        counters,
        budget,
        started: Instant::now(),
        records: Vec::new(),
        failure: None,
        hooked: false,
        witness,
    };
    if layouts.legacy {
        cursor.legacy = sweep_table(
            &mut sweep,
            &mut statements,
            "message",
            false,
            std::mem::take(&mut cursor.legacy),
        )?;
    }
    if layouts.v2 {
        cursor.v2 = sweep_table(
            &mut sweep,
            &mut statements,
            "session_message",
            true,
            std::mem::take(&mut cursor.v2),
        )?;
    }
    let records = std::mem::take(&mut sweep.records);
    let failure = sweep.failure;
    drop(sweep);
    drop(statements);
    drop(work);
    transaction.commit().map_err(sqlite_failure)?;
    let cursor_key = Some(serde_json::to_string(&cursor).map_err(|_| FailureCode::Store)?);
    Ok(SqliteBatch {
        records,
        cursor_key,
        failure,
        complete_sweep: cursor.legacy.done && cursor.v2.done,
    })
}

struct Layouts {
    legacy: bool,
    v2: bool,
}

/// Columns of one table admitted from the schema; wider tables are not an OpenCode layout.
const MAX_SCHEMA_COLUMNS: usize = 64;

/// Rows schema admission can emit at most: the encoding pragma plus, for each of the five
/// tables, one existence row and at most `MAX_SCHEMA_COLUMNS + 1` column rows.
const ADMISSION_ROWS_RESERVE: u32 = 1 + 5 * (1 + MAX_SCHEMA_COLUMNS as u32 + 1);

fn table_columns(
    transaction: &Transaction<'_>,
    table: &str,
    rows: &mut u32,
) -> Result<Option<HashSet<String>>, FailureCode> {
    let exists: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
            [table],
            |row| row.get(0),
        )
        .map_err(sqlite_failure)?;
    *rows = rows.saturating_add(1);
    if !exists {
        return Ok(None);
    }
    let mut statement = transaction
        .prepare("SELECT name FROM pragma_table_info(?1) LIMIT ?2")
        .map_err(sqlite_failure)?;
    // The bound is applied by SQLite before any result is collected, one row past the limit.
    let columns = statement
        .query_map(params![table, MAX_SCHEMA_COLUMNS as i64 + 1], |row| {
            row.get::<_, String>(0)
        })
        .map_err(sqlite_failure)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(sqlite_failure)?;
    *rows = rows.saturating_add(u32::try_from(columns.len()).unwrap_or(u32::MAX));
    if columns.len() > MAX_SCHEMA_COLUMNS {
        return Err(FailureCode::UnsupportedSchema);
    }
    Ok(Some(columns.into_iter().collect()))
}

fn has_columns(columns: &Option<HashSet<String>>, required: &[&str]) -> bool {
    columns
        .as_ref()
        .is_some_and(|columns| required.iter().all(|column| columns.contains(*column)))
}

/// A recognized layout must be complete: legacy needs `session`, `message` and `part`; v2 needs
/// `session_v2` and `session_message` (with `seq`). Partial layouts, and a database with neither
/// layout, are `unsupported_schema`, never an empty success.
fn validate_layouts(transaction: &Transaction<'_>, rows: &mut u32) -> Result<Layouts, FailureCode> {
    let encoding: String = transaction
        .query_row("PRAGMA encoding", [], |row| row.get(0))
        .map_err(sqlite_failure)?;
    *rows = rows.saturating_add(1);
    if encoding != "UTF-8" {
        return Err(FailureCode::UnsupportedSchema);
    }
    let session = table_columns(transaction, "session", rows)?;
    let message = table_columns(transaction, "message", rows)?;
    let part = table_columns(transaction, "part", rows)?;
    let session_v2 = table_columns(transaction, "session_v2", rows)?;
    let session_message = table_columns(transaction, "session_message", rows)?;
    let legacy = message.is_some() || part.is_some();
    let v2 = session_message.is_some() || session_v2.is_some();
    if legacy
        && !(has_columns(&session, &["id"])
            && has_columns(&message, MESSAGE_COLUMNS)
            && has_columns(&part, PART_COLUMNS))
    {
        return Err(FailureCode::UnsupportedSchema);
    }
    if v2 && !(has_columns(&session_v2, &["id"]) && has_columns(&session_message, V2_COLUMNS)) {
        return Err(FailureCode::UnsupportedSchema);
    }
    if !legacy && !v2 {
        return Err(FailureCode::UnsupportedSchema);
    }
    for (present, table) in [(legacy, "message"), (v2, "session_message")] {
        if present {
            // Cursors are rowids; a WITHOUT ROWID table has none.
            transaction
                .prepare(&format!("SELECT rowid FROM {table} LIMIT 0"))
                .map_err(|_| FailureCode::UnsupportedSchema)?;
        }
    }
    Ok(Layouts { legacy, v2 })
}

fn sqlite_failure(error: rusqlite::Error) -> FailureCode {
    match error {
        rusqlite::Error::SqliteFailure(code, _) => match code.code {
            rusqlite::ffi::ErrorCode::DatabaseBusy | rusqlite::ffi::ErrorCode::DatabaseLocked => {
                FailureCode::Busy
            }
            rusqlite::ffi::ErrorCode::DatabaseCorrupt => FailureCode::Corrupt,
            rusqlite::ffi::ErrorCode::NotADatabase => FailureCode::NotSqlite,
            rusqlite::ffi::ErrorCode::TooBig => FailureCode::RecordTooLarge,
            rusqlite::ffi::ErrorCode::OperationInterrupted => FailureCode::LimitExceeded,
            _ => FailureCode::Sqlite,
        },
        _ => FailureCode::Sqlite,
    }
}

/// Decodes the five counters and total of an OpenCode or usage-shaped object.
///
/// Every present, valid counter is kept independently; a record with no counter at all is not
/// usage. A derived total needs all five components, but that only decides the aggregate.
fn decode_tokens(
    object: &serde_json::Map<String, Value>,
) -> Result<(TokenComponents, Option<u64>), DecodeError> {
    let (components, explicit_total) = if let Some(tokens) = object.get("tokens") {
        decode_open_code_tokens(tokens)?
    } else if let Some(usage) = object.get("usage") {
        let usage = usage.as_object().ok_or(DecodeError::InvalidRecord)?;
        (
            TokenComponents {
                input: optional_count(usage, "input_tokens")?,
                output: optional_count(usage, "output_tokens")?,
                reasoning: None,
                cache_read: optional_count(usage, "cache_read_input_tokens")?,
                cache_write: optional_count(usage, "cache_creation_input_tokens")?,
            },
            None,
        )
    } else {
        return Err(DecodeError::NotUsage);
    };
    validate_total_range(&components, explicit_total)?;
    let any_counter = explicit_total.is_some()
        || [
            components.input,
            components.output,
            components.reasoning,
            components.cache_read,
            components.cache_write,
        ]
        .iter()
        .any(Option::is_some);
    if !any_counter {
        return Err(DecodeError::NotUsage);
    }
    Ok((components, explicit_total))
}

fn decode_open_code_tokens(value: &Value) -> Result<(TokenComponents, Option<u64>), DecodeError> {
    let tokens = value.as_object().ok_or(DecodeError::InvalidRecord)?;
    let cache = match tokens.get("cache") {
        Some(Value::Null) | None => None,
        Some(value) => Some(value.as_object().ok_or(DecodeError::InvalidRecord)?),
    };
    Ok((
        TokenComponents {
            input: optional_count(tokens, "input")?,
            output: optional_count(tokens, "output")?,
            reasoning: optional_count(tokens, "reasoning")?,
            cache_read: cache
                .map(|cache| optional_count(cache, "read"))
                .transpose()?
                .flatten(),
            cache_write: cache
                .map(|cache| optional_count(cache, "write"))
                .transpose()?
                .flatten(),
        },
        optional_count(tokens, "total")?,
    ))
}

fn validate_total_range(
    components: &TokenComponents,
    explicit_total: Option<u64>,
) -> Result<(), DecodeError> {
    validate_component_range(components)?;
    if explicit_total.is_none() {
        let complete = [
            components.input,
            components.output,
            components.reasoning,
            components.cache_read,
            components.cache_write,
        ]
        .into_iter()
        .all(|value| value.is_some());
        if complete
            && components
                .checked_total()
                .is_none_or(|total| total > MAX_TOKEN_COUNT)
        {
            return Err(DecodeError::InvalidRecord);
        }
    }
    Ok(())
}

pub fn resolve_candidates(
    candidates: impl IntoIterator<Item = RecordCandidate>,
) -> Result<Vec<ResolvedCandidate>, ResolveError> {
    let mut by_record = BTreeMap::<String, Vec<RecordCandidate>>::new();
    for candidate in candidates {
        by_record
            .entry(candidate.record_id())
            .or_default()
            .push(candidate);
    }
    let mut resolved = Vec::with_capacity(by_record.len());
    for (_, mut mirrors) in by_record {
        mirrors.sort_by(|left, right| {
            left.format_rank.cmp(&right.format_rank).then_with(|| {
                left.canonical_path
                    .as_os_str()
                    .as_encoded_bytes()
                    .cmp(right.canonical_path.as_os_str().as_encoded_bytes())
            })
        });
        for pair in mirrors.windows(2) {
            let same_candidate = pair[0].format_rank == pair[1].format_rank
                && pair[0].canonical_path == pair[1].canonical_path;
            if same_candidate && pair[0].fingerprint != pair[1].fingerprint {
                return Err(ResolveError::SourceChanging);
            }
        }
        let winner = mirrors.remove(0);
        let mirror_conflict = mirrors
            .iter()
            .any(|mirror| !same_observation(&winner, mirror));
        resolved.push(ResolvedCandidate {
            record: winner,
            mirror_conflict,
        });
    }
    resolved.sort_by(|left, right| {
        left.record
            .record_id()
            .as_bytes()
            .cmp(right.record.record_id().as_bytes())
    });
    Ok(resolved)
}

/// Whether two mirror observations of one record agree on every reported value.
pub fn same_observation(left: &RecordCandidate, right: &RecordCandidate) -> bool {
    left.occurred_at_ms == right.occurred_at_ms
        && left.components == right.components
        && left.total == right.total
        && left.selected_part_ids == right.selected_part_ids
}

fn optional_count(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<u64>, DecodeError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => number
            .as_u64()
            .filter(|count| *count <= MAX_TOKEN_COUNT)
            .map(Some)
            .ok_or(DecodeError::InvalidRecord),
        Some(_) => Err(DecodeError::InvalidRecord),
    }
}

fn sum_component(values: impl Iterator<Item = Option<u64>>) -> Result<Option<u64>, DecodeError> {
    let mut sum = 0_u64;
    for value in values {
        let Some(value) = value else {
            return Ok(None);
        };
        sum = sum.checked_add(value).ok_or(DecodeError::InvalidRecord)?;
    }
    Ok(Some(sum))
}

pub fn fingerprint(bytes: &[u8]) -> u64 {
    fingerprint_extend(0xcbf2_9ce4_8422_2325, bytes)
}

fn fingerprint_extend(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}
