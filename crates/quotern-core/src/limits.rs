pub const MAX_PATH_BYTES: usize = 4096;
pub const MAX_FILE_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_OPENCODE_RECORD_BYTES: usize = 256 * 1024;
pub const MAX_TOKEN_COUNT: u64 = 1_000_000_000_000;
pub const MAX_RECORD_ID_COMPONENT_BYTES: usize = 256;
pub const MAX_SOURCE_BYTES_PER_PASS: u64 = 64 * 1024 * 1024;
pub const MAX_DIRECTORY_ENTRIES: u32 = 20_000;
pub const MAX_METADATA_CALLS: u32 = 40_000;
pub const MAX_HEADER_READS: u32 = 256;
pub const MAX_DIRECTORY_OPENS: u32 = 64;
/// Simultaneously held directory iterators, including the synchronous JSON-part iterator.
pub const MAX_OPEN_DIRECTORIES: usize = 8;
pub const MAX_DIRECTORY_DEPTH: usize = 8;
pub const MAX_FRONTIER_DIRECTORIES: usize = 4096;
pub const MAX_METADATA_SPOOL_ROWS: usize = 200_000;
pub const MAX_METADATA_SPOOL_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_SQLITE_ROWS_PER_PASS: u32 = 5_000;
pub const MAX_SOURCE_DATABASES_PER_PASS: u32 = 64;
pub const MAX_REPORTED_SOURCES: usize = 64;
pub const MAX_RECORD_ID_BYTES: usize = 512;
pub const MAX_MODEL_BYTES: usize = 256;
pub const MAX_SELECTED_PART_IDS: usize = 256;
/// Bytes of the SQLite v2 `type` column that can be materialized before the column is rejected.
pub const MAX_SQLITE_TYPE_BYTES: usize = 32;
/// Durable acquisition-failure rows retained per source.
pub const MAX_FAILED_FILES: usize = 1_024;
/// Persisted known source paths revalidated first in each pass.
pub const MAX_KNOWN_PATHS_PER_PASS: usize = 4_096;
/// Largest raw observation page returned by the history API.
pub const MAX_OBSERVATION_PAGE: usize = 1_000;
/// Largest durable acquisition cursor: a group cursor carries at most `MAX_SELECTED_PART_IDS`
/// decoded parts of bounded identity and six bounded counters each.
pub const MAX_PROGRESS_CURSOR_BYTES: usize = 256 * 1024;
/// Latest accepted source timestamp: 9999-12-31T23:59:59.999Z in UTC epoch milliseconds.
pub const MAX_SOURCE_TIMESTAMP_MS: i64 = 253_402_300_799_999;
/// SQLite virtual-machine instructions between progress callbacks.
pub const SQLITE_PROGRESS_INTERVAL: i32 = 1_000;
/// Progress callbacks allowed per source read before SQLite is interrupted.
pub const SQLITE_MAX_PROGRESS_TICKS: u64 = 200_000;
pub const SQLITE_BUSY_TIMEOUT_MS: u64 = 250;
pub const SQLITE_PASS_DEADLINE_MS: u64 = 1_000;
pub const SOURCE_CHANGING_RETRIES: u8 = 3;
pub const RETRY_INITIAL_MS: u64 = 5_000;
pub const RETRY_MAX_MS: u64 = 5 * 60 * 1_000;
/// Largest `-wal` an existing history may carry for admission; longer is refused unread.
pub const ADMISSION_WAL_BYTES: u64 = 64 * 1024 * 1024;
/// Most bytes the one admission read transaction may read from the main file and log frames.
pub const ADMISSION_READ_BYTES: u64 = 8 * 1024 * 1024;
/// Most enabled `sources` rows admission reads; a further row is refused.
pub const ADMISSION_ENABLED_SOURCES: usize = 64;
