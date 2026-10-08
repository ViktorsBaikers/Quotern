//! Versioned C ABI (v1) over the Rust core. Every export returns Rust-allocated JSON envelopes
//! released exactly once by `quotern_string_free`; no export unwinds across C.
//!
//! The crate holds no domain rules: it validates the wire, owns one core [`Engine`] behind a
//! mutex per handle, and maps core results to the fixed error table.

use std::ffi::{CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use quotern_core::domain::SourceKind;
use quotern_core::domain::{ConsentState, FailureCode, SourceAuthorization};
use quotern_core::ingest::fs::RealSourceFs;
use quotern_core::ingest::{Engine, IngestError, TodayError};
use quotern_core::limits::MAX_SOURCE_TIMESTAMP_MS;
use quotern_core::snapshot::WindowError;
use quotern_core::store::{StoreError, StoreErrorCode, store_error_code};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const ABI_VERSION: u32 = 1;
const MAX_CONFIG_BYTES: usize = 65_536;
const MAX_REQUEST_BYTES: usize = 65_536;
const MAX_METHOD_BYTES: usize = 64;
const MAX_FIELD_BYTES: usize = 4_096;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_CUSTOM_ROOTS: usize = 16;

/// Opaque engine handle: one core Engine (and so at most one Store) behind a mutex.
pub struct QuoternEngine {
    failed: AtomicBool,
    #[cfg(feature = "test-faults")]
    queued: std::sync::atomic::AtomicUsize,
    state: Mutex<Engine<RealSourceFs>>,
}

/// A cancel token: a boxed atomic flag.
pub struct QuoternCancel {
    flag: AtomicBool,
}

/// Test boundary: callers of `engine` past the first failed-flag check and waiting for its lock.
///
/// # Safety
/// `engine` is a live handle from a successful open.
#[cfg(feature = "test-faults")]
pub unsafe fn queued_waiters(engine: *const QuoternEngine) -> usize {
    unsafe { &*engine }.queued.load(Ordering::SeqCst)
}

struct ApiError {
    code: &'static str,
    message: String,
    retryable: bool,
}

impl ApiError {
    fn fixed(code: &'static str, message: &str, retryable: bool) -> Self {
        Self {
            code,
            message: message.to_owned(),
            retryable,
        }
    }

    fn invalid(field: &str) -> Self {
        Self::fixed(
            "invalid_request",
            &format!("invalid request: {field}"),
            false,
        )
    }

    fn limit(bound: &str) -> Self {
        Self::fixed("limit_exceeded", &format!("limit exceeded: {bound}"), false)
    }

    fn engine_failed() -> Self {
        Self::fixed("engine_failed", "engine failed", false)
    }

    fn internal_panic() -> Self {
        Self::fixed("internal_panic", "internal panic", false)
    }
}

fn store_api_error(error: &StoreError) -> ApiError {
    match store_error_code(error) {
        StoreErrorCode::StoreBusy => ApiError::fixed("store_busy", "store busy", true),
        StoreErrorCode::SourceOverlapConflict => {
            ApiError::fixed("source_overlap_conflict", "source overlap conflict", false)
        }
        StoreErrorCode::StoreNewerVersion => {
            ApiError::fixed("store_newer_version", "store newer version", false)
        }
        StoreErrorCode::LimitExceeded(bound) => ApiError::limit(bound),
        StoreErrorCode::StoreMigrationFailed => {
            ApiError::fixed("store_migration_failed", "store migration failed", true)
        }
        StoreErrorCode::StoreCorrupt => ApiError::fixed("store_corrupt", "store corrupt", false),
    }
}

/// Serializes the envelope; a response over 1 MiB becomes `limit_exceeded: response_bytes`. An
/// envelope that cannot be serialized is answered `internal_panic` with `true`, so the caller
/// fails the handle it belongs to.
fn respond(result: Result<Value, ApiError>) -> (*mut c_char, bool) {
    let envelope = |result: &Result<Value, ApiError>| match result {
        Ok(data) => json!({"v": 1, "ok": true, "data": data}),
        Err(error) => json!({"v": 1, "ok": false, "error": {
            "code": error.code, "message": error.message, "retryable": error.retryable
        }}),
    };
    let bytes = match serde_json::to_vec(&envelope(&result)) {
        Ok(bytes) if bytes.len() <= MAX_RESPONSE_BYTES => Ok(bytes),
        Ok(_) => serde_json::to_vec(&envelope(&Err(ApiError::limit("response_bytes")))),
        Err(error) => Err(error),
    };
    match bytes.ok().and_then(|bytes| CString::new(bytes).ok()) {
        Some(text) => (text.into_raw(), false),
        None => (
            CString::new(r#"{"v":1,"ok":false,"error":{"code":"internal_panic","message":"internal panic","retryable":false}}"#)
                .map_or(std::ptr::null_mut(), CString::into_raw),
            true,
        ),
    }
}

/// Length of the NUL-terminated string at `pointer` if it is at most `max`; the scan stops at
/// `max + 1` bytes, so an unterminated or longer input is never read further.
///
/// # Safety
/// `pointer` is non-null and readable up to its NUL or `max + 1` bytes.
unsafe fn bounded_len(pointer: *const c_char, max: usize) -> Option<usize> {
    (0..=max).find(|&index| unsafe { *pointer.add(index) } == 0)
}

unsafe fn bounded_bytes<'a>(pointer: *const c_char, max: usize) -> Option<&'a [u8]> {
    let length = unsafe { bounded_len(pointer, max) }?;
    Some(unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), length) })
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Config {
    data_dir: String,
    home: String,
}

fn absolute_field(value: &str, field: &str) -> Result<(), ApiError> {
    if value.len() > MAX_FIELD_BYTES || value.contains('\0') || !Path::new(value).is_absolute() {
        return Err(ApiError::invalid(field));
    }
    Ok(())
}

fn parse_config(text: &str) -> Result<Config, ApiError> {
    let config: Config = serde_json::from_str(text).map_err(|_| ApiError::invalid("config"))?;
    absolute_field(&config.data_dir, "data_dir")?;
    absolute_field(&config.home, "home")?;
    Ok(config)
}

/// # Safety
/// `config_json` is NULL or a NUL-terminated string; `out` is NULL or writable.
unsafe fn open_inner(
    config_json: *const c_char,
    out: *mut *mut QuoternEngine,
) -> Result<Value, ApiError> {
    if config_json.is_null() {
        return Err(ApiError::invalid("config_json"));
    }
    if out.is_null() {
        return Err(ApiError::invalid("out"));
    }
    let bytes = unsafe { bounded_bytes(config_json, MAX_CONFIG_BYTES) }
        .ok_or_else(|| ApiError::limit("config_bytes"))?;
    let text = std::str::from_utf8(bytes).map_err(|_| ApiError::invalid("config"))?;
    let config = parse_config(text)?;
    let mut engine: Engine<RealSourceFs> =
        Engine::open(Path::new(&config.data_dir), Path::new(&config.home));
    engine
        .load_existing(&RealSourceFs)
        .map_err(|error| store_api_error(&error))?;
    // Each persisted enabled root gets one reattach attempt; a failure is recorded as that
    // source's unattached overlay and never fails the open.
    let enabled = engine
        .enabled_source_ids()
        .map_err(|error| store_api_error(&error))?;
    for id in enabled {
        let _ = engine.reattach(RealSourceFs, &id, None);
    }
    let handle = Box::new(QuoternEngine {
        failed: AtomicBool::new(false),
        #[cfg(feature = "test-faults")]
        queued: std::sync::atomic::AtomicUsize::new(0),
        state: Mutex::new(engine),
    });
    unsafe { *out = Box::into_raw(handle) };
    Ok(json!({"abi_version": ABI_VERSION}))
}

#[unsafe(no_mangle)]
pub extern "C" fn quotern_abi_version() -> u32 {
    ABI_VERSION
}

/// # Safety
/// `config_json` is NULL or NUL-terminated; `out` is NULL or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quotern_engine_open(
    config_json: *const c_char,
    out: *mut *mut QuoternEngine,
) -> *mut c_char {
    if !out.is_null() {
        unsafe { *out = std::ptr::null_mut() };
    }
    let result = match catch_unwind(AssertUnwindSafe(|| unsafe { open_inner(config_json, out) })) {
        Ok(result) => result,
        Err(_) => {
            if !out.is_null() {
                unsafe { *out = std::ptr::null_mut() };
            }
            Err(ApiError::internal_panic())
        }
    };
    let (text, internal) = respond(result);
    if internal && !out.is_null() {
        // The caller is told the open failed, so the handle it would never close is closed here.
        unsafe { quotern_engine_close(*out) };
        unsafe { *out = std::ptr::null_mut() };
    }
    text
}

/// # Safety
/// `engine` is NULL or a handle from a successful open, closed at most once, with no call in
/// flight.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quotern_engine_close(engine: *mut QuoternEngine) {
    if engine.is_null() {
        return;
    }
    // Dropping the box never locks the mutex, so a poisoned or failed handle closes too.
    let _ = catch_unwind(AssertUnwindSafe(|| drop(unsafe { Box::from_raw(engine) })));
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SetSelection {
    harness: String,
    root: String,
    selected: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IngestRequest {
    now_ms: i64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TodayRequest {
    tz: String,
    now_ms: i64,
}

fn parse<'a, T: Deserialize<'a>>(request: &'a str) -> Result<T, ApiError> {
    serde_json::from_str(request).map_err(|_| ApiError::invalid("request"))
}

fn check_now(now_ms: i64) -> Result<(), ApiError> {
    if (0..=MAX_SOURCE_TIMESTAMP_MS).contains(&now_ms) {
        Ok(())
    } else {
        Err(ApiError::invalid("now_ms"))
    }
}

fn parse_selection(request: &str) -> Result<SetSelection, ApiError> {
    let request: SetSelection = parse(request)?;
    if request.harness != "opencode" {
        return Err(ApiError::invalid("harness"));
    }
    absolute_field(&request.root, "root")?;
    Ok(request)
}

fn parse_ingest(request: &str) -> Result<IngestRequest, ApiError> {
    let request: IngestRequest = parse(request)?;
    check_now(request.now_ms)?;
    Ok(request)
}

fn parse_today(request: &str) -> Result<TodayRequest, ApiError> {
    let request: TodayRequest = parse(request)?;
    if request.tz.len() > MAX_FIELD_BYTES {
        return Err(ApiError::invalid("tz"));
    }
    check_now(request.now_ms)?;
    Ok(request)
}

/// Test boundary: parses `request` for `method` (`open` for the config) through the production
/// parse and validation, then writes it back, so a shared request golden proves the codec both
/// ways. A refusal is its error message.
#[cfg(feature = "test-faults")]
pub fn request_round_trip(method: &str, request: &str) -> Result<String, String> {
    let written = match method {
        "open" => serde_json::to_string(&parse_config(request).map_err(|e| e.message)?),
        "set_source_selection" => {
            serde_json::to_string(&parse_selection(request).map_err(|e| e.message)?)
        }
        "list_sources" => serde_json::to_string(&parse::<Empty>(request).map_err(|e| e.message)?),
        "ingest" => serde_json::to_string(&parse_ingest(request).map_err(|e| e.message)?),
        "today_snapshot" => serde_json::to_string(&parse_today(request).map_err(|e| e.message)?),
        _ => return Err("unknown method".to_owned()),
    };
    written.map_err(|error| error.to_string())
}

fn sources(engine: &Engine<RealSourceFs>) -> Result<Value, ApiError> {
    let entries = engine
        .source_entries()
        .map_err(|error| store_api_error(&error))?;
    Ok(json!({"sources": entries}))
}

fn dispatch(
    engine: &mut Engine<RealSourceFs>,
    method: &str,
    request: &str,
    cancel: &AtomicBool,
) -> Result<Value, ApiError> {
    match method {
        "set_source_selection" => {
            let request = parse_selection(request)?;
            let root = Path::new(&request.root);
            let known = engine
                .find_registered(&RealSourceFs, root)
                .map_err(|error| store_api_error(&error))?;
            if !request.selected {
                let id = known.ok_or_else(|| ApiError::invalid("root"))?;
                engine.deny(&id).map_err(|error| store_api_error(&error))?;
                return sources(engine);
            }
            if known.is_none() {
                let custom = engine
                    .source_entries()
                    .map_err(|error| store_api_error(&error))?
                    .iter()
                    .filter(|entry| entry.kind == SourceKind::Custom)
                    .count();
                if custom >= MAX_CUSTOM_ROOTS {
                    return Err(ApiError::invalid("root"));
                }
            }
            let authorization = SourceAuthorization {
                selected: true,
                consent: ConsentState::Enabled,
            };
            if let Err(report) =
                engine.attach_opencode(RealSourceFs, root, authorization, SourceKind::Custom)
            {
                if let Some(error) = engine.last_store_error() {
                    return Err(store_api_error(error));
                }
                return Err(match report.failure {
                    Some(FailureCode::RootOverlap) => {
                        ApiError::fixed("source_overlap_conflict", "source overlap conflict", false)
                    }
                    Some(FailureCode::Store) => {
                        ApiError::fixed("store_corrupt", "store corrupt", false)
                    }
                    _ => ApiError::invalid("root"),
                });
            }
            sources(engine)
        }
        "list_sources" => {
            let _: Empty = parse(request)?;
            sources(engine)
        }
        "ingest" => {
            let request = parse_ingest(request)?;
            match engine.ingest(|| RealSourceFs, request.now_ms, cancel) {
                Ok(()) => sources(engine),
                Err(IngestError::Cancelled(_)) => {
                    Err(ApiError::fixed("cancelled", "cancelled", true))
                }
                Err(IngestError::Store(error)) => Err(store_api_error(&error)),
            }
        }
        "today_snapshot" => {
            let request = parse_today(request)?;
            match engine.today_snapshot(&request.tz, request.now_ms) {
                Ok(snapshot) => {
                    serde_json::to_value(snapshot).map_err(|_| ApiError::internal_panic())
                }
                Err(TodayError::Window(WindowError::UnknownZone)) => Err(ApiError::invalid("tz")),
                Err(TodayError::Window(WindowError::NowOutOfRange)) => {
                    Err(ApiError::invalid("now_ms"))
                }
                Err(TodayError::Store(error)) => Err(store_api_error(&error)),
            }
        }
        _ => Err(ApiError::fixed("unknown_method", "unknown method", false)),
    }
}

/// # Safety
/// All pointers are NULL or valid as documented in `quotern.h`.
unsafe fn call_inner(
    engine: *mut QuoternEngine,
    method: *const c_char,
    request_json: *const c_char,
    cancel: *const QuoternCancel,
) -> Result<Value, ApiError> {
    if engine.is_null() {
        return Err(ApiError::invalid("engine"));
    }
    let handle = unsafe { &*engine };
    if handle.failed.load(Ordering::Acquire) {
        return Err(ApiError::engine_failed());
    }
    if method.is_null() {
        return Err(ApiError::invalid("method"));
    }
    if request_json.is_null() {
        return Err(ApiError::invalid("request_json"));
    }
    let method_bytes = unsafe { bounded_bytes(method, MAX_METHOD_BYTES) }
        .ok_or_else(|| ApiError::limit("method_bytes"))?;
    let request_bytes = unsafe { bounded_bytes(request_json, MAX_REQUEST_BYTES) }
        .ok_or_else(|| ApiError::limit("request_bytes"))?;
    let method = std::str::from_utf8(method_bytes).map_err(|_| ApiError::invalid("method"))?;
    let request = std::str::from_utf8(request_bytes).map_err(|_| ApiError::invalid("request"))?;
    #[cfg(feature = "test-faults")]
    handle.queued.fetch_add(1, Ordering::SeqCst);
    let locked = handle.state.lock();
    #[cfg(feature = "test-faults")]
    handle.queued.fetch_sub(1, Ordering::SeqCst);
    let mut guard = match locked {
        Ok(guard) => guard,
        Err(_) => {
            handle.failed.store(true, Ordering::Release);
            return Err(ApiError::engine_failed());
        }
    };
    if handle.failed.load(Ordering::Acquire) {
        return Err(ApiError::engine_failed());
    }
    let never = AtomicBool::new(false);
    let flag = if cancel.is_null() {
        &never
    } else {
        unsafe { &(*cancel).flag }
    };
    // The panic is caught while the guard is held, so the mutex is never poisoned by it; the
    // handle is marked failed instead and never resumes domain work. Every `internal_panic`
    // result, a serialization failure included, fails the handle the same way.
    let result = catch_unwind(AssertUnwindSafe(|| {
        dispatch(&mut guard, method, request, flag)
    }))
    .unwrap_or_else(|_| Err(ApiError::internal_panic()));
    if matches!(&result, Err(error) if error.code == "internal_panic") {
        handle.failed.store(true, Ordering::Release);
    }
    result
}

/// # Safety
/// `engine` is NULL or a live handle; `method` and `request_json` are NULL or NUL-terminated;
/// `cancel` is NULL or a live token that outlives the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quotern_call(
    engine: *mut QuoternEngine,
    method: *const c_char,
    request_json: *const c_char,
    cancel: *const QuoternCancel,
) -> *mut c_char {
    let result = catch_unwind(AssertUnwindSafe(|| unsafe {
        call_inner(engine, method, request_json, cancel)
    }))
    .unwrap_or_else(|_| Err(ApiError::internal_panic()));
    let failed = matches!(&result, Err(error) if error.code == "internal_panic");
    let (text, internal) = respond(result);
    if (failed || internal) && !engine.is_null() {
        unsafe { &*engine }.failed.store(true, Ordering::Release);
    }
    text
}

#[unsafe(no_mangle)]
pub extern "C" fn quotern_cancel_new() -> *mut QuoternCancel {
    Box::into_raw(Box::new(QuoternCancel {
        flag: AtomicBool::new(false),
    }))
}

/// # Safety
/// `cancel` is NULL or a live token.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quotern_cancel_trigger(cancel: *const QuoternCancel) {
    if !cancel.is_null() {
        unsafe { &*cancel }.flag.store(true, Ordering::Release);
    }
}

/// # Safety
/// `cancel` is NULL or a token from `quotern_cancel_new`, freed once and not in use.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quotern_cancel_free(cancel: *mut QuoternCancel) {
    if !cancel.is_null() {
        drop(unsafe { Box::from_raw(cancel) });
    }
}

/// # Safety
/// `text` is NULL or a string returned by this library, freed once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn quotern_string_free(text: *mut c_char) {
    if !text.is_null() {
        drop(unsafe { CString::from_raw(text) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    /// A durable source list that cannot be read at open fails the open with its mapped store
    /// error and leaves `out` NULL, never an empty success.
    #[test]
    fn open_with_unreadable_source_list_fails_with_its_store_error()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let base = directory.path().canonicalize()?;
        let (source, home, data) = (base.join("source"), base.join("home"), base.join("data"));
        std::fs::create_dir(&source)?;
        std::fs::create_dir(&home)?;
        {
            let mut engine: Engine<RealSourceFs> = Engine::open(&data, &home);
            let authorization = SourceAuthorization {
                selected: true,
                consent: ConsentState::Enabled,
            };
            engine
                .attach_opencode(RealSourceFs, &source, authorization, SourceKind::Custom)
                .map_err(|report| format!("attach: {report:?}"))?;
        }
        // Outside denied rows past the source bound: admission reads only enabled rows and
        // admits the store, the durable list is refused.
        let outside = rusqlite::Connection::open(data.join("history.sqlite"))?;
        for index in 0..64 {
            outside.execute(
                "INSERT INTO sources(source_id, harness, canonical_root, kind, consent) \
                 VALUES(?1, 'opencode', ?2, 'custom', 'denied')",
                rusqlite::params![format!("{index:032}"), format!("/outside/{index}")],
            )?;
        }
        drop(outside);
        let config =
            CString::new(json!({"data_dir": data.to_str(), "home": home.to_str()}).to_string())?;
        let mut out: *mut QuoternEngine = std::ptr::null_mut();
        let response = unsafe { quotern_engine_open(config.as_ptr(), &mut out) };
        let text = unsafe { CStr::from_ptr(response) }.to_str()?.to_owned();
        unsafe { quotern_string_free(response) };
        if !out.is_null() {
            unsafe { quotern_engine_close(out) };
        }
        assert_eq!(
            serde_json::from_str::<Value>(&text)?,
            json!({"v": 1, "ok": false, "error": {
                "code": "limit_exceeded", "message": "limit exceeded: store_limit", "retryable": false
            }})
        );
        assert!(out.is_null(), "a failed open leaves out NULL");
        Ok(())
    }
}
