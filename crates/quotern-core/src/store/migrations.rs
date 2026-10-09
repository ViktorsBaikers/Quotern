use rusqlite::{Connection, Transaction, TransactionBehavior};

use super::StoreError;

pub const VERSION: i64 = 1;

// Store v1 has never shipped, so its definition is revised in place rather than migrated. A
// store written with an earlier unshipped v1 shape is refused untouched, never altered.
const V1: &str = r#"
CREATE TABLE sources (
    source_id TEXT PRIMARY KEY,
    harness TEXT NOT NULL CHECK (harness IN ('opencode', 'codex')),
    canonical_root TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL CHECK (kind IN ('builtin', 'env', 'custom')),
    consent TEXT NOT NULL CHECK (consent IN ('undecided', 'enabled', 'denied')),
    generation INTEGER NOT NULL DEFAULT 0 CHECK (generation >= 0),
    root_device INTEGER,
    root_inode INTEGER,
    change_count INTEGER NOT NULL DEFAULT 0 CHECK (change_count >= 0),
    next_retry_ms INTEGER,
    retry_reason TEXT CHECK (retry_reason IS NULL OR retry_reason IN ('source_changing', 'source_idle', 'busy')),
    generation_failure TEXT,
    dirty INTEGER NOT NULL DEFAULT 0 CHECK (dirty IN (0, 1)),
    known_clock INTEGER NOT NULL DEFAULT 0 CHECK (known_clock >= 0)
);
CREATE TABLE source_files (
    source_id TEXT NOT NULL REFERENCES sources(source_id),
    relative_path TEXT NOT NULL,
    device INTEGER NOT NULL,
    inode INTEGER NOT NULL,
    size INTEGER NOT NULL CHECK (size >= 0),
    mtime_ns INTEGER NOT NULL,
    byte_offset INTEGER NOT NULL CHECK (byte_offset >= 0),
    first_line_fnv64 INTEGER NOT NULL,
    adapter_state TEXT NOT NULL,
    parse_generation INTEGER NOT NULL,
    file_state TEXT NOT NULL CHECK (file_state IN ('present', 'missing', 'replaced', 'rejected')),
    visit_seq INTEGER NOT NULL DEFAULT 0 CHECK (visit_seq >= 0),
    header_id TEXT CHECK (header_id IS NULL OR length(CAST(header_id AS BLOB)) BETWEEN 1 AND 256),
    header_state TEXT,
    header_era TEXT,
    record_state TEXT,
    tail_state TEXT CHECK (tail_state IS NULL OR tail_state IN ('pending', 'discarding')),
    uncovered_from_ms INTEGER,
    uncovered_to_ms INTEGER,
    PRIMARY KEY (source_id, relative_path),
    CHECK ((uncovered_from_ms IS NULL) = (uncovered_to_ms IS NULL) AND (uncovered_from_ms IS NULL OR (uncovered_from_ms >= 0 AND uncovered_from_ms <= uncovered_to_ms))),
    CHECK (CASE adapter_state WHEN 'codex_jsonl' THEN (byte_offset > 0 OR first_line_fnv64 = 0) AND (header_state IS NULL OR header_state IN ('own', 'own_forked', 'foreign_first_line', 'appended_header')) AND record_state IN ('none', 'inherited', 'prefix', 'own') AND (header_era IS NULL OR header_era IN ('record', 'legacy')) AND (header_era IS NOT NULL) = COALESCE(header_state IN ('own', 'own_forked', 'appended_header'), 0) ELSE header_id IS NULL AND header_state IS NULL AND header_era IS NULL AND record_state IS NULL AND tail_state IS NULL AND uncovered_from_ms IS NULL END)
);
CREATE INDEX source_files_known ON source_files(source_id, adapter_state, file_state, visit_seq, mtime_ns DESC, relative_path);
CREATE TABLE usage_events (
    event_key TEXT PRIMARY KEY,
    family TEXT NOT NULL CHECK (family IN ('opencode', 'codex')),
    measurement_kind TEXT NOT NULL CHECK (measurement_kind = 'source_reported'),
    harness TEXT NOT NULL CHECK (harness IN ('opencode', 'codex')),
    source_id TEXT NOT NULL REFERENCES sources(source_id),
    session_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    occurred_at_ms INTEGER NOT NULL CHECK (occurred_at_ms >= 0),
    input_tokens INTEGER CHECK (input_tokens IS NULL OR input_tokens >= 0),
    output_tokens INTEGER CHECK (output_tokens IS NULL OR output_tokens >= 0),
    reasoning_tokens INTEGER CHECK (reasoning_tokens IS NULL OR reasoning_tokens >= 0),
    cache_read_tokens INTEGER CHECK (cache_read_tokens IS NULL OR cache_read_tokens >= 0),
    cache_write_tokens INTEGER CHECK (cache_write_tokens IS NULL OR cache_write_tokens >= 0),
    total_tokens INTEGER CHECK (total_tokens IS NULL OR total_tokens >= 0),
    total_provenance TEXT CHECK (total_provenance IS NULL OR total_provenance IN ('reported', 'derived')),
    source_convention TEXT,
    acquisition_consistency TEXT NOT NULL CHECK (acquisition_consistency IN ('sqlite_read_transaction', 'file_by_file_best_effort')),
    origin_uncertainty TEXT NOT NULL CHECK (origin_uncertainty = 'unverified_origin'),
    total_mismatch INTEGER NOT NULL CHECK (total_mismatch IN (0, 1)),
    mirror_conflict INTEGER NOT NULL CHECK (mirror_conflict IN (0, 1)),
    selected_part_ids TEXT NOT NULL,
    format_rank INTEGER NOT NULL,
    mirror_path TEXT NOT NULL,
    pending_partial INTEGER NOT NULL DEFAULT 0 CHECK (pending_partial IN (0, 1)),
    pending_reason TEXT,
    revision INTEGER NOT NULL CHECK (revision > 0),
    first_seen_ms INTEGER NOT NULL,
    updated_ms INTEGER NOT NULL,
    CHECK ((total_tokens IS NULL) = (total_provenance IS NULL)),
    CHECK ((total_provenance IS 'derived') = (source_convention IS NOT NULL)),
    CHECK (source_convention IS NULL OR source_convention = 'codexbar-3239175f-disjoint'),
    CHECK (CASE family WHEN 'opencode' THEN harness = 'opencode' AND substr(event_key, 1, 6) IS NOT 'codex:' WHEN 'codex' THEN harness = 'codex' AND substr(event_key, 1, 6) IS 'codex:' AND total_provenance IS NOT 'derived' AND acquisition_consistency = 'file_by_file_best_effort' AND total_mismatch = 0 AND selected_part_ids = '[]' AND format_rank = 0 AND pending_partial = 0 AND pending_reason IS NULL ELSE 0 END)
);
CREATE INDEX usage_events_occurred_at ON usage_events(occurred_at_ms);
CREATE INDEX usage_events_source ON usage_events(source_id, occurred_at_ms, event_key);
CREATE TABLE reported_groups (
    source_id TEXT NOT NULL REFERENCES sources(source_id),
    event_key TEXT NOT NULL,
    format_rank INTEGER NOT NULL,
    mirror_path TEXT NOT NULL,
    session_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    occurred_at_ms INTEGER NOT NULL CHECK (occurred_at_ms >= 0),
    input_tokens INTEGER CHECK (input_tokens IS NULL OR input_tokens >= 0),
    output_tokens INTEGER CHECK (output_tokens IS NULL OR output_tokens >= 0),
    reasoning_tokens INTEGER CHECK (reasoning_tokens IS NULL OR reasoning_tokens >= 0),
    cache_read_tokens INTEGER CHECK (cache_read_tokens IS NULL OR cache_read_tokens >= 0),
    cache_write_tokens INTEGER CHECK (cache_write_tokens IS NULL OR cache_write_tokens >= 0),
    total_tokens INTEGER CHECK (total_tokens IS NULL OR total_tokens >= 0),
    total_provenance TEXT CHECK (total_provenance IS NULL OR total_provenance IN ('reported', 'derived')),
    source_convention TEXT,
    acquisition_consistency TEXT NOT NULL CHECK (acquisition_consistency IN ('sqlite_read_transaction', 'file_by_file_best_effort')),
    part_ids TEXT NOT NULL,
    pending_partial INTEGER NOT NULL CHECK (pending_partial IN (0, 1)),
    pending_reason TEXT,
    generation INTEGER NOT NULL,
    PRIMARY KEY (source_id, event_key, format_rank, mirror_path),
    CHECK ((total_tokens IS NULL) = (total_provenance IS NULL)),
    CHECK ((total_provenance IS 'derived') = (source_convention IS NOT NULL)),
    CHECK (source_convention IS NULL OR source_convention = 'codexbar-3239175f-disjoint')
);
CREATE INDEX reported_groups_event ON reported_groups(event_key, format_rank, mirror_path);
CREATE INDEX reported_groups_path ON reported_groups(source_id, mirror_path);
CREATE TABLE group_baseline (
    source_id TEXT NOT NULL REFERENCES sources(source_id),
    generation INTEGER NOT NULL,
    event_key TEXT NOT NULL,
    format_rank INTEGER NOT NULL,
    mirror_path TEXT NOT NULL,
    prior_json TEXT,
    PRIMARY KEY (source_id, generation, event_key, format_rank, mirror_path)
);
CREATE TABLE source_projection_totals (
    source_id TEXT PRIMARY KEY REFERENCES sources(source_id),
    records INTEGER NOT NULL CHECK (records >= 0),
    input_count INTEGER NOT NULL CHECK (input_count >= 0),
    input_sum INTEGER NOT NULL CHECK (input_sum >= 0),
    output_count INTEGER NOT NULL CHECK (output_count >= 0),
    output_sum INTEGER NOT NULL CHECK (output_sum >= 0),
    reasoning_count INTEGER NOT NULL CHECK (reasoning_count >= 0),
    reasoning_sum INTEGER NOT NULL CHECK (reasoning_sum >= 0),
    cache_read_count INTEGER NOT NULL CHECK (cache_read_count >= 0),
    cache_read_sum INTEGER NOT NULL CHECK (cache_read_sum >= 0),
    cache_write_count INTEGER NOT NULL CHECK (cache_write_count >= 0),
    cache_write_sum INTEGER NOT NULL CHECK (cache_write_sum >= 0),
    total_count INTEGER NOT NULL CHECK (total_count >= 0),
    total_sum INTEGER NOT NULL CHECK (total_sum >= 0),
    derived_total_count INTEGER NOT NULL CHECK (derived_total_count >= 0),
    mismatch_count INTEGER NOT NULL CHECK (mismatch_count >= 0),
    conflict_count INTEGER NOT NULL CHECK (conflict_count >= 0),
    pending_count INTEGER NOT NULL CHECK (pending_count >= 0),
    sqlite_count INTEGER NOT NULL CHECK (sqlite_count >= 0),
    json_count INTEGER NOT NULL CHECK (json_count >= 0)
);
CREATE TABLE opencode_progress (
    source_id TEXT NOT NULL REFERENCES sources(source_id),
    acquisition_path TEXT NOT NULL,
    generation INTEGER NOT NULL,
    working_cursor_key TEXT,
    identity TEXT,
    PRIMARY KEY (source_id, acquisition_path)
);
CREATE TABLE acquisition_failures (
    source_id TEXT NOT NULL REFERENCES sources(source_id),
    relative_path TEXT NOT NULL,
    code TEXT NOT NULL,
    attempts INTEGER NOT NULL CHECK (attempts >= 1),
    PRIMARY KEY (source_id, relative_path)
);
CREATE TABLE frontier_directories (
    source_id TEXT NOT NULL REFERENCES sources(source_id),
    generation INTEGER NOT NULL,
    relative_path TEXT NOT NULL,
    depth INTEGER NOT NULL CHECK (depth >= 0),
    ordinal INTEGER NOT NULL,
    restart_blocked INTEGER NOT NULL CHECK (restart_blocked IN (0, 1)),
    PRIMARY KEY (source_id, generation, relative_path)
);
CREATE TABLE metadata_spool (
    source_id TEXT NOT NULL REFERENCES sources(source_id),
    generation INTEGER NOT NULL,
    relative_path TEXT NOT NULL,
    device INTEGER NOT NULL,
    inode INTEGER NOT NULL,
    size INTEGER NOT NULL CHECK (size >= 0),
    mtime_ns INTEGER NOT NULL,
    parser_kind TEXT NOT NULL,
    PRIMARY KEY (source_id, generation, relative_path)
);
CREATE TABLE opencode_candidate_spool (
    source_id TEXT NOT NULL REFERENCES sources(source_id),
    generation INTEGER NOT NULL,
    relative_path TEXT NOT NULL,
    event_key TEXT NOT NULL,
    format_rank INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    candidate_json TEXT NOT NULL,
    PRIMARY KEY (source_id, generation, relative_path, event_key, format_rank, fingerprint)
);
CREATE TABLE source_status (
    source_id TEXT PRIMARY KEY REFERENCES sources(source_id),
    last_attempt_ms INTEGER,
    last_success_ms INTEGER,
    last_error_code TEXT,
    outcome TEXT NOT NULL CHECK (outcome IN ('consistent', 'catching_up', 'partial', 'unavailable')),
    entry_count INTEGER NOT NULL CHECK (entry_count >= 0),
    stat_count INTEGER NOT NULL CHECK (stat_count >= 0),
    header_count INTEGER NOT NULL CHECK (header_count >= 0),
    directory_count INTEGER NOT NULL CHECK (directory_count >= 0),
    source_open_count INTEGER NOT NULL CHECK (source_open_count >= 0),
    row_count INTEGER NOT NULL CHECK (row_count >= 0),
    bytes_count INTEGER NOT NULL CHECK (bytes_count >= 0),
    rejected_count INTEGER NOT NULL CHECK (rejected_count >= 0)
);
"#;

/// Refuses a store written by a newer version without touching it.
pub fn check_version(current: i64) -> rusqlite::Result<()> {
    if current > VERSION {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}

/// One schema object as SQLite records it: kind, name, table and defining SQL.
pub type SchemaRow = (String, String, String, Option<String>);

/// Every object of a database, in a fixed order. The set is the bounded list of v1 objects plus
/// whatever a foreign store holds; its size never depends on stored history.
pub fn schema_rows(connection: &Connection) -> rusqlite::Result<Vec<SchemaRow>> {
    let mut statement = connection.prepare(
        "SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name LIMIT 256",
    )?;
    statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect()
}

/// The exact v1 object set, built from the same DDL in a scratch in-memory database.
fn expected_schema() -> rusqlite::Result<Vec<SchemaRow>> {
    let scratch = Connection::open_in_memory()?;
    scratch.execute_batch(V1)?;
    schema_rows(&scratch)
}

/// Admits a database with a bounded metadata comparison only: it is a fresh empty store, or it
/// carries exactly the amended v1 objects. History rows are never read.
fn sqlite<T>(result: rusqlite::Result<T>) -> Result<T, StoreError> {
    result.map_err(|_| StoreError::Sqlite)
}

pub fn admit(connection: &Connection) -> Result<Admission, StoreError> {
    let current: i64 =
        sqlite(connection.pragma_query_value(None, "user_version", |row| row.get(0)))?;
    if check_version(current).is_err() {
        return Err(StoreError::UnsupportedVersion);
    }
    let rows = sqlite(schema_rows(connection))?;
    if current == 0 {
        return if rows.is_empty() {
            Ok(Admission::Fresh)
        } else {
            Err(StoreError::Corrupt)
        };
    }
    if rows == sqlite(expected_schema())? {
        Ok(Admission::Current)
    } else {
        Err(StoreError::Corrupt)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admission {
    Fresh,
    Current,
}

/// Creates the complete v1 schema in one transaction for a fresh store; an existing store is
/// verified against it, never altered.
pub fn migrate(connection: &mut Connection) -> Result<(), StoreError> {
    match admit(connection)? {
        Admission::Current => Ok(()),
        Admission::Fresh => {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|_| StoreError::Sqlite)?;
            // The empty state was verified before the write lock; verify it again under it.
            if admit(&transaction)? != Admission::Fresh {
                return Err(StoreError::Corrupt);
            }
            apply_v1(&transaction).map_err(|_| StoreError::Sqlite)?;
            #[cfg(feature = "test-faults")]
            if CREATION_FAULT.with(|fault| fault.replace(false)) {
                // Interrupted after the schema statements ran, before the commit: dropping the
                // transaction rolls everything back.
                return Err(StoreError::Sqlite);
            }
            transaction
                .pragma_update(None, "user_version", VERSION)
                .map_err(|_| StoreError::Sqlite)?;
            #[cfg(feature = "test-faults")]
            {
                // The hook runs with the complete schema and version written but uncommitted.
                let hook = CREATION_HOOK.with(|slot| slot.borrow_mut().take());
                if let Some(hook) = hook {
                    hook(&transaction);
                }
            }
            transaction.commit().map_err(|_| StoreError::Sqlite)
        }
    }
}

#[cfg(feature = "test-faults")]
thread_local! {
    static CREATION_FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Test boundary: the next fresh store creation on this thread is interrupted after its schema
/// statements and before its commit.
#[cfg(feature = "test-faults")]
pub fn interrupt_next_creation() {
    CREATION_FAULT.with(|fault| fault.set(true));
}

#[cfg(feature = "test-faults")]
type CreationHook = Box<dyn FnOnce(&Connection)>;

#[cfg(feature = "test-faults")]
thread_local! {
    static CREATION_HOOK: std::cell::RefCell<Option<CreationHook>> =
        const { std::cell::RefCell::new(None) };
}

/// Test boundary: runs `hook` once, on this thread's next fresh store creation, after the schema
/// and `user_version` statements ran and immediately before the commit. It receives the
/// still-uncommitted transaction, so a test can stop the process while the creation is live.
#[cfg(feature = "test-faults")]
pub fn set_creation_hook(hook: Option<CreationHook>) {
    CREATION_HOOK.with(|slot| *slot.borrow_mut() = hook);
}

fn apply_v1(transaction: &Transaction<'_>) -> rusqlite::Result<()> {
    transaction.execute_batch(V1)
}
