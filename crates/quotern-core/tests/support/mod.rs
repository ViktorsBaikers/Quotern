#![allow(dead_code)]

pub mod vfs_probe;

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use rusqlite::Connection;
use tempfile::TempDir;

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Complete supported OpenCode schema (legacy `session`/`message`/`part` and v2
/// `session_v2`/`session_message`) without any journal-mode pragma.
pub const SCHEMA: &str = "
CREATE TABLE session (id TEXT PRIMARY KEY, parent_id TEXT, directory TEXT, title TEXT, time_created INTEGER);
CREATE TABLE message (id TEXT NOT NULL, session_id TEXT NOT NULL, time_created INTEGER, data BLOB NOT NULL, PRIMARY KEY (id, session_id));
CREATE TABLE part (id TEXT NOT NULL, message_id TEXT NOT NULL, session_id TEXT NOT NULL, time_created INTEGER, data BLOB NOT NULL, PRIMARY KEY (id, message_id));
CREATE INDEX part_message_id_id_idx ON part(message_id, id);
CREATE TABLE session_v2 (id TEXT PRIMARY KEY, parent_id TEXT, directory TEXT, title TEXT, time_created INTEGER);
CREATE TABLE session_message (id TEXT NOT NULL, session_id TEXT NOT NULL, type TEXT NOT NULL, seq INTEGER NOT NULL, time_created INTEGER, data BLOB NOT NULL, PRIMARY KEY (id, session_id));
";

/// Lower-case hex of `bytes`, for passing arbitrary payloads through the line protocol.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// SQL blob literal for `bytes`.
pub fn sql_blob(bytes: &[u8]) -> String {
    format!("x'{}'", hex(bytes))
}

/// A throw-away source/data/home triple.
pub struct Roots {
    pub directory: TempDir,
    pub source: PathBuf,
    pub data: PathBuf,
    pub home: PathBuf,
}

impl Roots {
    pub fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("source");
        let data = directory.path().join("data");
        let home = directory.path().join("home");
        std::fs::create_dir(&source)?;
        std::fs::create_dir(&home)?;
        Ok(Self {
            directory,
            source,
            data,
            home,
        })
    }
}

/// Rollback-journal fixture database: no WAL or SHM sidecar exists, so it is readable while it
/// stays open in this process and carries none of the live-WAL sharing hazards.
pub fn rollback_database(path: &Path) -> TestResult<Connection> {
    let connection = Connection::open(path)?;
    connection.execute_batch(SCHEMA)?;
    Ok(connection)
}

/// Child process that holds a database open in WAL mode, as a live OpenCode writer would.
pub struct WriterChild {
    pub child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    stopped: bool,
}

impl WriterChild {
    /// `entry` is the `#[test]` in the calling binary that runs [`writer_child_main`].
    pub fn start(entry: &str, path: &Path, mode: &str) -> TestResult<Self> {
        Self::spawn(
            entry,
            &[
                ("QUOTERN_OPENCODE_WAL_WRITER", path.as_os_str()),
                (
                    "QUOTERN_OPENCODE_WAL_WRITER_MODE",
                    std::ffi::OsStr::new(mode),
                ),
            ],
            "READY",
        )
    }

    /// Re-executes the test binary at test `entry` with `envs` and waits for the `ready` line.
    pub fn spawn(entry: &str, envs: &[(&str, &std::ffi::OsStr)], ready: &str) -> TestResult<Self> {
        let mut command = Command::new(std::env::current_exe()?);
        command.args(["--exact", entry, "--nocapture"]);
        for (key, value) in envs {
            command.env(key, value);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let input = child.stdin.take().ok_or("writer stdin unavailable")?;
        let output = child.stdout.take().ok_or("writer stdout unavailable")?;
        let mut writer = Self {
            child,
            input,
            output: BufReader::new(output),
            stopped: false,
        };
        writer.wait_for(ready)?;
        Ok(writer)
    }

    pub fn wait_for(&mut self, expected: &str) -> TestResult {
        let mut line = String::new();
        loop {
            line.clear();
            if self.output.read_line(&mut line)? == 0 {
                return Err(format!("writer exited before {expected}").into());
            }
            if line.trim() == expected {
                return Ok(());
            }
        }
    }

    pub fn command(&mut self, command: &str, expected: &str) -> TestResult {
        writeln!(self.input, "{command}")?;
        self.input.flush()?;
        self.wait_for(expected)
    }

    /// Runs `sql` on the holding connection (one statement batch, committed on return).
    pub fn exec(&mut self, sql: &str) -> TestResult {
        self.command(&format!("exec {}", hex(sql.as_bytes())), "EXECUTED")
    }

    pub fn stop(&mut self) -> TestResult {
        self.command("exit", "CLOSED")?;
        let status = self.child.wait()?;
        self.stopped = true;
        assert!(status.success(), "writer child exited with {status}");
        Ok(())
    }

    pub fn crash(&mut self) -> TestResult {
        self.child.kill()?;
        let status = self.child.wait()?;
        assert!(
            !status.success(),
            "writer child exited successfully after forced termination"
        );
        self.stopped = true;
        Ok(())
    }
}

impl Drop for WriterChild {
    fn drop(&mut self) {
        if !self.stopped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Body of the re-executed test binary acting as an OpenCode writer. Without the role variables
/// (a normal test run) it does nothing.
pub fn writer_child_main() -> TestResult {
    let Ok(path) = std::env::var("QUOTERN_OPENCODE_WAL_WRITER") else {
        return Ok(());
    };
    let connection = Connection::open(path)?;
    let mode: String = connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
    assert_eq!(mode, "wal");
    connection.pragma_update(None, "wal_autocheckpoint", 0)?;
    let role =
        std::env::var("QUOTERN_OPENCODE_WAL_WRITER_MODE").unwrap_or_else(|_| "seed".to_owned());
    match role.as_str() {
        "seed" => connection.execute_batch(
            "CREATE TABLE records(id TEXT PRIMARY KEY);\
             INSERT INTO records VALUES ('initial');\
             CREATE TABLE session_v2(\
                 id TEXT PRIMARY KEY, parent_id TEXT, directory TEXT, title TEXT, time_created INTEGER\
             );\
             CREATE TABLE session_message(\
                 id TEXT NOT NULL, session_id TEXT NOT NULL, type TEXT NOT NULL, seq INTEGER NOT NULL,\
                 time_created INTEGER, data BLOB NOT NULL, PRIMARY KEY(id, session_id)\
             );\
             INSERT INTO session_v2(id) VALUES ('peer-session');\
             INSERT INTO session_message VALUES(\
                 'derived-42', 'peer-session', 'assistant', 1, 1700000001000,\
                 '{\"tokens\":{\"input\":10,\"output\":20,\"reasoning\":3,\"cache\":{\"read\":4,\"write\":5}}}'\
             );",
        )?,
        "hold" => {
            let has_opencode_schema: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'session_message')",
                [],
                |row| row.get(0),
            )?;
            assert!(has_opencode_schema, "holding writer requires an OpenCode fixture database");
        }
        other => return Err(format!("unknown writer mode: {other}").into()),
    }
    println!("READY");
    std::io::stdout().flush()?;
    for command in std::io::stdin().lock().lines() {
        let command = command?;
        match command.as_str() {
            "append" => {
                connection.execute("INSERT INTO records VALUES ('later')", [])?;
                connection.execute(
                    "INSERT INTO session_message VALUES(\
                        'later-message', 'peer-session', 'assistant', 2, 1700000001000,\
                        '{\"tokens\":{\"input\":1,\"output\":1,\"reasoning\":0,\"cache\":{\"read\":0,\"write\":0}}}'\
                    )",
                    [],
                )?;
                println!("COMMITTED");
                std::io::stdout().flush()?;
            }
            "exclusive" => {
                connection.pragma_update(None, "locking_mode", "EXCLUSIVE")?;
                connection.execute_batch("BEGIN EXCLUSIVE;")?;
                println!("LOCKED");
                std::io::stdout().flush()?;
            }
            "release" => {
                connection.execute_batch("ROLLBACK;")?;
                connection.pragma_update(None, "locking_mode", "NORMAL")?;
                println!("RELEASED");
                std::io::stdout().flush()?;
            }
            "exit" => {
                drop(connection);
                println!("CLOSED");
                std::io::stdout().flush()?;
                return Ok(());
            }
            other if other.starts_with("exec ") => {
                let hex_sql = &other["exec ".len()..];
                let bytes = (0..hex_sql.len())
                    .step_by(2)
                    .map(|index| u8::from_str_radix(&hex_sql[index..index + 2], 16))
                    .collect::<Result<Vec<_>, _>>()?;
                connection.execute_batch(std::str::from_utf8(&bytes)?)?;
                println!("EXECUTED");
                std::io::stdout().flush()?;
            }
            other => return Err(format!("unknown writer command: {other}").into()),
        }
    }
    Ok(())
}

/// Entry-point name used by both integration binaries.
pub const WRITER_ENTRY: &str = "sqlite_writer_child_entrypoint";

/// Starts a writer that creates and seeds a v2 OpenCode database.
pub fn start_writer(path: &Path) -> TestResult<WriterChild> {
    WriterChild::start(WRITER_ENTRY, path, "seed")
}

/// Starts a writer that holds an existing OpenCode database open in WAL mode.
pub fn start_existing_writer(path: &Path) -> TestResult<WriterChild> {
    WriterChild::start(WRITER_ENTRY, path, "hold")
}

/// Test-only observer of the process's native filesystem API boundary (macOS arm64 only).
///
/// It exports the C symbols `stat`, `lstat`, `fstat`, `fstatat`, `readlink`, `access`,
/// `realpath`, `opendir`, `fdopendir`, `closedir`, `readdir`, `readdir_r`, `read`, `pread`,
/// `readv`, `preadv` and `close` from the test executable, so every call made by code linked into
/// it (the production source code, Rust `std`, and the bundled SQLite C code) lands here first and
/// is forwarded to the next definition (`dlsym(RTLD_NEXT)`, i.e. libsystem). The production
/// accounting (`tick`, `charge`, `HOOK_STATS`) is neither read nor written: the observer sits
/// beneath those callbacks, SQLite's syscall table still points at the production hooks, and the
/// hooks' "original" entries are these exported symbols.
///
/// What it proves: attempts crossing the native API boundary with a source-root path or a
/// source-root descriptor, and the kernel access mode (`F_GETFL`) of every source descriptor at
/// each metadata, read and close call made through it (so a descriptor a library opens and holds
/// without a path-based call is still checked while live). What it does not: raw kernel syscalls,
/// libsystem-internal path walks (for example the lstat chain inside libc `realpath`),
/// mmap-consumed bytes, `open` itself (a variadic function whose arguments cannot be forwarded
/// from a Rust definition), or any other target. Foreign-thread source work, table overflow,
/// failed closes and descriptors whose access cannot be read are coverage faults.
///
/// Isolation and bounds: it replaces process-wide symbols, so each test that arms it runs in a
/// re-executed single-test child (`--test-threads=1`) and arms it only after its fixtures exist.
/// All state is fixed-size and allocated before arming; no native call is ever made while the
/// state lock is held, every hook returns the native result and leaves `errno` exactly as the
/// native call (or, for `readdir`, the caller) left it, and dropping the armed observer disarms
/// it.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub mod physical_native {
    use std::cell::Cell;
    use std::ffi::{CStr, c_char, c_int, c_void};
    use std::marker::PhantomData;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::rc::Rc;
    use std::sync::{LazyLock, Mutex};

    /// Normative per-pass ceilings, written as literals on purpose (not the production constants).
    pub const METADATA_CEILING: u64 = 40_000;
    pub const OPEN_CEILING: u64 = 64;
    pub const HELD_CEILING: u64 = 8;
    pub const YIELD_CEILING: u64 = 20_000;
    /// The raw-read-byte ceiling of the JSON-only quantity (materialized JSON bytes). SQLite page
    /// reads are not bounded by it; see [`json_within`].
    pub const JSON_BYTE_CEILING: u64 = 67_108_864;

    const F_GETPATH: c_int = 50;
    const F_GETFL: c_int = 3;
    const O_ACCMODE: c_int = 3;
    const DIRECTORY_TABLE: usize = 128;
    const DESCRIPTOR_TABLE: usize = 1024;
    const TRACE_TABLE: usize = 512; // first 512 metadata calls of a pass

    #[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
    pub struct Counts {
        /// stat, lstat, fstat, fstatat, readlink, access and realpath attempts.
        pub metadata: u64,
        /// opendir and fdopendir attempts, failed ones included.
        pub opens: u64,
        /// Non-dot directory results (plus read errors) returned to the caller.
        pub yields: u64,
        /// Directory streams open right now.
        pub held: u64,
        /// Highest `held` since the last `begin_pass`.
        pub peak: u64,
        /// Positive bytes returned by read, pread, readv and preadv.
        pub bytes: u64,
        /// Source-descriptor calls whose descriptor the kernel reports as open for writing.
        pub writable: u64,
        pub coverage_faults: u64,
    }

    /// How many calls made through a source descriptor had its kernel access mode checked, by
    /// kind of file (the sidecar suffix of the descriptor's path).
    #[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
    pub struct Reach {
        pub wal: u64,
        pub shm: u64,
        pub other: u64,
    }

    /// The metadata-class call behind one counted metadata attempt.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Meta {
        Stat,
        Lstat,
        Fstat,
        Fstatat,
        Readlink,
        Access,
        Realpath,
    }

    const METAS: [Meta; 7] = [
        Meta::Stat,
        Meta::Lstat,
        Meta::Fstat,
        Meta::Fstatat,
        Meta::Readlink,
        Meta::Access,
        Meta::Realpath,
    ];

    struct State {
        root: Vec<u8>,
        alias: Vec<u8>,
        owner: usize,
        counts: Counts,
        reach: Reach,
        trace: [(u8, c_int); TRACE_TABLE],
        trace_len: usize,
        directories: [(usize, c_int); DIRECTORY_TABLE],
        descriptors: [c_int; DESCRIPTOR_TABLE],
    }

    static STATE: Mutex<Option<State>> = Mutex::new(None);

    thread_local! {
        static FOCUS: Cell<u32> = const { Cell::new(0) };
    }

    unsafe extern "C" {
        fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
        fn __error() -> *mut c_int;
        fn abort() -> !;
        // SDK: `pthread_t pthread_self(void)`, with `pthread_t` a pointer to an opaque struct.
        fn pthread_self() -> *mut c_void;
        fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
        fn dirfd(directory: *mut c_void) -> c_int;
    }

    /// Runs `change` on the armed state. A poisoned lock is recovered and recorded as a fault.
    /// Callers resolve everything native first: nothing here calls into the C library.
    fn state<T>(change: impl FnOnce(&mut State) -> T) -> Option<T> {
        let mut guard = STATE.lock().unwrap_or_else(|poisoned| {
            let mut guard = poisoned.into_inner();
            if let Some(state) = guard.as_mut() {
                state.counts.coverage_faults += 1;
            }
            guard
        });
        guard.as_mut().map(change)
    }

    fn path_is_source(state: &State, bytes: &[u8]) -> bool {
        [&state.root, &state.alias].into_iter().any(|root| {
            bytes == root.as_slice()
                || (bytes.starts_with(root) && bytes.get(root.len()) == Some(&b'/'))
        })
    }

    /// The path of a descriptor, or of a caller-supplied C string, copied out before any lock.
    struct Resolved {
        bytes: [u8; 1024],
        length: usize,
    }

    impl Resolved {
        const NONE: Self = Self {
            bytes: [0; 1024],
            length: 0,
        };

        fn of_fd(fd: c_int) -> Self {
            let mut resolved = Self::NONE;
            if fd >= 0 {
                // SAFETY: F_GETPATH fills a buffer of at least MAXPATHLEN (1024) bytes.
                let found = unsafe { fcntl(fd, F_GETPATH, resolved.bytes.as_mut_ptr()) } == 0;
                if found {
                    resolved.length = resolved.bytes.iter().position(|b| *b == 0).unwrap_or(0);
                }
            }
            resolved
        }

        fn bytes(&self) -> &[u8] {
            &self.bytes[..self.length]
        }

        fn kind(&self) -> Kind {
            let bytes = self.bytes();
            if bytes.ends_with(b"-wal") {
                Kind::Wal
            } else if bytes.ends_with(b"-shm") {
                Kind::Shm
            } else {
                Kind::Other
            }
        }
    }

    #[derive(Clone, Copy)]
    enum Kind {
        Wal,
        Shm,
        Other,
    }

    enum Target {
        Path(*const c_char),
        Fd(c_int),
        /// `fstatat`: a source descriptor only decides for a path relative to it; an absolute
        /// pathname ignores the descriptor, so it is judged by the pathname alone.
        At(c_int, *const c_char),
        Directory(usize),
    }

    fn selected(target: Target) -> bool {
        let focus = FOCUS.with(Cell::get) > 0;
        // SAFETY: pthread_self has no preconditions.
        let current = unsafe { pthread_self() } as usize;
        // Everything native is resolved before the lock is taken.
        let resolved = match target {
            Target::Fd(fd) | Target::At(fd, _) if !focus => Resolved::of_fd(fd),
            _ => Resolved::NONE,
        };
        state(|state| {
            let hit = match target {
                Target::Path(path) => {
                    focus
                        || (!path.is_null()
                            // SAFETY: the caller of the native API passed a NUL-terminated path.
                            && path_is_source(state, unsafe { CStr::from_ptr(path) }.to_bytes()))
                }
                Target::Fd(fd) => {
                    focus
                        || (fd >= 0 && state.descriptors.contains(&fd))
                        || path_is_source(state, resolved.bytes())
                }
                Target::At(fd, path) => {
                    // SAFETY: a non-null path is NUL-terminated.
                    let relative = !path.is_null() && unsafe { *path } as u8 != b'/';
                    focus
                        || (!path.is_null()
                            // SAFETY: as above.
                            && path_is_source(state, unsafe { CStr::from_ptr(path) }.to_bytes()))
                        || (relative
                            && ((fd >= 0 && state.descriptors.contains(&fd))
                                || path_is_source(state, resolved.bytes())))
                }
                Target::Directory(stream) => {
                    stream != 0 && state.directories.iter().any(|entry| entry.0 == stream)
                }
            };
            if hit && current != state.owner {
                state.counts.coverage_faults += 1;
            }
            hit
        })
        .unwrap_or(false)
    }

    fn note(hit: bool, change: impl FnOnce(&mut State)) {
        if hit {
            state(change);
        }
    }

    fn own_descriptor(state: &mut State, fd: c_int) {
        if fd < 0 || state.descriptors.contains(&fd) {
            return;
        }
        match state.descriptors.iter_mut().find(|entry| **entry == -1) {
            Some(entry) => *entry = fd,
            None => state.counts.coverage_faults += 1,
        }
    }

    fn release_descriptor(state: &mut State, fd: c_int) {
        for entry in &mut state.descriptors {
            if *entry == fd {
                *entry = -1;
            }
        }
    }

    fn stream_opened(hit: bool, stream: *mut c_void) {
        if !hit || stream.is_null() {
            return;
        }
        // SAFETY: `stream` is the live DIR* the native call just returned.
        let fd = unsafe { dirfd(stream) };
        note(true, |state| {
            if fd < 0 {
                state.counts.coverage_faults += 1;
            }
            if let Some(entry) = state.directories.iter_mut().find(|entry| entry.0 == 0) {
                *entry = (stream as usize, fd);
                own_descriptor(state, fd);
                state.counts.held += 1;
                state.counts.peak = state.counts.peak.max(state.counts.held);
            } else {
                state.counts.coverage_faults += 1;
            }
        });
    }

    fn stream_closed(hit: bool, stream: *mut c_void, result: c_int) {
        note(hit, |state| {
            if result != 0 {
                state.counts.coverage_faults += 1;
                return;
            }
            match state
                .directories
                .iter_mut()
                .find(|entry| entry.0 == stream as usize)
            {
                Some(entry) => {
                    let fd = entry.1;
                    *entry = (0, -1);
                    release_descriptor(state, fd);
                    state.counts.held = state.counts.held.saturating_sub(1);
                }
                None => state.counts.coverage_faults += 1,
            }
        });
    }

    /// macOS `struct dirent` (64-bit inode layout).
    #[repr(C)]
    pub struct Dirent {
        inode: u64,
        seek_offset: u64,
        record_length: u16,
        name_length: u16,
        kind: u8,
        name: [c_char; 1024],
    }

    #[repr(C)]
    pub struct Iovec {
        base: *mut c_void,
        length: usize,
    }

    fn yielded(hit: bool, entry: *const Dirent, error: bool) {
        if !hit {
            return;
        }
        if error {
            note(true, |state| state.counts.yields += 1);
            return;
        }
        if !entry.is_null() {
            // SAFETY: a non-null result is a valid dirent with a NUL-terminated name.
            let name = unsafe { CStr::from_ptr((*entry).name.as_ptr()) }.to_bytes();
            if name != b"." && name != b".." {
                note(true, |state| state.counts.yields += 1);
            }
        }
    }

    /// The next (native) definition of `$symbol`, resolved once with `dlsym(RTLD_NEXT)`.
    macro_rules! next_symbol {
        ($name:ident, $next:ident, $symbol:literal, ($($ty:ty),*) -> $ret:ty) => {
            fn $next() -> unsafe extern "C" fn($($ty),*) -> $ret {
                static NEXT: LazyLock<usize> = LazyLock::new(|| {
                    // SAFETY: RTLD_NEXT (-1) looks the symbol up after this executable.
                    let found = unsafe {
                        dlsym((-1_isize) as *mut c_void, concat!($symbol, "\0").as_ptr().cast())
                    };
                    if found.is_null() || found as usize == $name as *const () as usize {
                        // SAFETY: nothing sensible can continue without the native symbol.
                        unsafe { abort() }
                    }
                    found as usize
                });
                // SAFETY: the address is the native definition of this exact C signature.
                unsafe {
                    std::mem::transmute::<usize, unsafe extern "C" fn($($ty),*) -> $ret>(*NEXT)
                }
            }
        };
    }

    macro_rules! hook {
        (
            $name:ident, $next:ident, $symbol:literal,
            ($($arg:ident: $ty:ty),*) -> $ret:ty,
            $target:expr, $before:expr, $after:expr
        ) => {
            next_symbol!($name, $next, $symbol, ($($ty),*) -> $ret);

            #[unsafe(export_name = $symbol)]
            pub unsafe extern "C" fn $name($($arg: $ty),*) -> $ret {
                // SAFETY: errno is thread-local; it is preserved around the observation.
                let incoming = unsafe { *__error() };
                let native = $next();
                let hit = selected($target);
                ($before)(hit);
                unsafe { *__error() = incoming };
                // SAFETY: the arguments are exactly those the caller supplied for this symbol.
                let result = unsafe { native($($arg),*) };
                let outgoing = unsafe { *__error() };
                ($after)(hit, result);
                unsafe { *__error() = outgoing };
                result
            }
        };
    }

    next_symbol!(observe_readdir, next_readdir, "readdir", (*mut c_void) -> *mut Dirent);

    /// Bare `readdir` reports the end and an error alike with NULL. errno is zeroed for the call
    /// itself, so a NULL with a nonzero errno is an error raised by this very call (a yielded
    /// result), whatever stale value the caller left; the caller's errno is restored on a clean
    /// end and the native one is passed through on an error.
    #[unsafe(export_name = "readdir")]
    pub unsafe extern "C" fn observe_readdir(stream: *mut c_void) -> *mut Dirent {
        // SAFETY: errno is thread-local.
        let incoming = unsafe { *__error() };
        let native = next_readdir();
        let hit = selected(Target::Directory(stream as usize));
        unsafe { *__error() = 0 };
        // SAFETY: `stream` is exactly what the caller supplied.
        let result = unsafe { native(stream) };
        let outgoing = unsafe { *__error() };
        yielded(hit, result, result.is_null() && outgoing != 0);
        unsafe { *__error() = if outgoing != 0 { outgoing } else { incoming } };
        result
    }

    fn metadata(hit: bool, which: Meta, fd: c_int) {
        note(hit, |state| {
            state.counts.metadata += 1;
            if state.trace_len < TRACE_TABLE {
                state.trace[state.trace_len] = (which as u8, fd);
                state.trace_len += 1;
            }
        });
    }

    fn open_attempt(hit: bool) {
        note(hit, |state| state.counts.opens += 1);
    }

    /// A call made through a source descriptor: its kernel access mode is read while the
    /// descriptor is live and counted, so a descriptor opened for writing is seen whichever
    /// library opened it and whether or not it was ever reached by path.
    fn descriptor_used(hit: bool, fd: c_int) {
        if !hit {
            return;
        }
        let kind = Resolved::of_fd(fd).kind();
        // SAFETY: F_GETFL takes no argument.
        let flags = unsafe { fcntl(fd, F_GETFL) };
        note(true, |state| {
            match kind {
                Kind::Wal => state.reach.wal += 1,
                Kind::Shm => state.reach.shm += 1,
                Kind::Other => state.reach.other += 1,
            }
            if flags < 0 {
                state.counts.coverage_faults += 1;
            } else if flags & O_ACCMODE != 0 {
                state.counts.writable += 1;
            }
        });
    }

    fn nothing(_: bool) {}

    fn ignore_int(_: bool, _: c_int) {}

    fn ignore_pointer(_: bool, _: *mut c_char) {}

    fn bytes_read(hit: bool, count: isize) {
        if count > 0 {
            note(hit, |state| state.counts.bytes += count as u64);
        }
    }

    hook!(observe_stat, next_stat, "stat",
        (path: *const c_char, _buffer: *mut c_void) -> c_int,
        Target::Path(path), |hit| metadata(hit, Meta::Stat, -1), ignore_int);
    hook!(observe_lstat, next_lstat, "lstat",
        (path: *const c_char, _buffer: *mut c_void) -> c_int,
        Target::Path(path), |hit| metadata(hit, Meta::Lstat, -1), ignore_int);
    hook!(observe_fstat, next_fstat, "fstat",
        (fd: c_int, _buffer: *mut c_void) -> c_int,
        Target::Fd(fd),
        |hit| {
            metadata(hit, Meta::Fstat, fd);
            descriptor_used(hit, fd);
        },
        |hit, result| if result == 0 { note(hit, |state| own_descriptor(state, fd)) });
    hook!(observe_fstatat, next_fstatat, "fstatat",
        (fd: c_int, path: *const c_char, _buffer: *mut c_void, _flags: c_int) -> c_int,
        Target::At(fd, path), |hit| metadata(hit, Meta::Fstatat, -1), ignore_int);
    hook!(observe_readlink, next_readlink, "readlink",
        (path: *const c_char, _buffer: *mut c_char, _size: usize) -> isize,
        Target::Path(path), |hit| metadata(hit, Meta::Readlink, -1), |_, _: isize| {});
    hook!(observe_access, next_access, "access",
        (path: *const c_char, _mode: c_int) -> c_int,
        Target::Path(path), |hit| metadata(hit, Meta::Access, -1), ignore_int);
    hook!(observe_realpath, next_realpath, "realpath",
        (path: *const c_char, _buffer: *mut c_char) -> *mut c_char,
        Target::Path(path), |hit| metadata(hit, Meta::Realpath, -1), ignore_pointer);
    hook!(observe_realpath_ext, next_realpath_ext, "realpath$DARWIN_EXTSN",
        (path: *const c_char, _buffer: *mut c_char) -> *mut c_char,
        Target::Path(path), |hit| metadata(hit, Meta::Realpath, -1), ignore_pointer);
    hook!(observe_opendir, next_opendir, "opendir",
        (path: *const c_char) -> *mut c_void,
        Target::Path(path), open_attempt, stream_opened);
    hook!(observe_fdopendir, next_fdopendir, "fdopendir",
        (fd: c_int) -> *mut c_void,
        Target::Fd(fd), open_attempt, stream_opened);
    hook!(observe_closedir, next_closedir, "closedir",
        (stream: *mut c_void) -> c_int,
        Target::Directory(stream as usize), nothing,
        |hit, result| stream_closed(hit, stream, result));
    hook!(observe_readdir_r, next_readdir_r, "readdir_r",
        (stream: *mut c_void, entry: *mut Dirent, out: *mut *mut Dirent) -> c_int,
        Target::Directory(stream as usize), nothing,
        |hit, result| yielded(hit, if result == 0 { unsafe { *out } } else { std::ptr::null_mut() }, result != 0));
    hook!(observe_read, next_read, "read",
        (fd: c_int, _buffer: *mut c_void, _count: usize) -> isize,
        Target::Fd(fd), |hit| descriptor_used(hit, fd), bytes_read);
    hook!(observe_pread, next_pread, "pread",
        (fd: c_int, _buffer: *mut c_void, _count: usize, _offset: i64) -> isize,
        Target::Fd(fd), |hit| descriptor_used(hit, fd), bytes_read);
    hook!(observe_readv, next_readv, "readv",
        (fd: c_int, _vectors: *const Iovec, _count: c_int) -> isize,
        Target::Fd(fd), |hit| descriptor_used(hit, fd), bytes_read);
    hook!(observe_preadv, next_preadv, "preadv",
        (fd: c_int, _vectors: *const Iovec, _count: c_int, _offset: i64) -> isize,
        Target::Fd(fd), |hit| descriptor_used(hit, fd), bytes_read);
    hook!(observe_close, next_close, "close",
    (fd: c_int) -> c_int,
    Target::Fd(fd), |hit| descriptor_used(hit, fd),
    |hit, result| note(hit, |state| {
        if result == 0 {
            release_descriptor(state, fd);
        } else {
            state.counts.coverage_faults += 1;
        }
    }));

    /// Attributes every native call this thread makes while it lives to the source, whatever its
    /// path: the ancestor probes (`/`, `/private`, ...) of a canonicalization. `!Send`/`!Sync`.
    pub struct Focus(PhantomData<Rc<()>>);

    impl Focus {
        pub fn enter() -> Self {
            FOCUS.with(|value| value.set(value.get() + 1));
            Self(PhantomData)
        }
    }

    impl Drop for Focus {
        fn drop(&mut self) {
            FOCUS.with(|value| value.set(value.get() - 1));
        }
    }

    /// The armed observer; at most one exists, bound to the thread that started it.
    pub struct Observer(PhantomData<Rc<()>>);

    impl Observer {
        /// Arms the observer for the absolute `root` (matched under both its given and canonical
        /// spellings, since `/tmp` and `/private/tmp` name the same tree).
        pub fn start(root: &Path) -> Self {
            assert!(root.is_absolute(), "observer root must be absolute");
            let alias = root.as_os_str().as_bytes().to_vec();
            let canonical = std::fs::canonicalize(root)
                .expect("observer root must exist")
                .as_os_str()
                .as_bytes()
                .to_vec();
            // Resolve every native symbol before arming so no lookup happens under observation.
            let _ = (next_stat(), next_lstat(), next_fstat(), next_fstatat());
            let _ = (
                next_readlink(),
                next_access(),
                next_realpath(),
                next_realpath_ext(),
            );
            let _ = (next_opendir(), next_fdopendir(), next_closedir());
            let _ = (next_readdir_r(), next_readdir());
            let _ = (
                next_read(),
                next_pread(),
                next_readv(),
                next_preadv(),
                next_close(),
            );
            let mut guard = STATE.lock().expect("observer state");
            assert!(guard.is_none(), "a physical observer is already armed");
            *guard = Some(State {
                root: canonical,
                alias,
                // SAFETY: pthread_self has no preconditions.
                owner: unsafe { pthread_self() } as usize,
                counts: Counts::default(),
                reach: Reach::default(),
                trace: [(0, -1); TRACE_TABLE],
                trace_len: 0,
                directories: [(0, -1); DIRECTORY_TABLE],
                descriptors: [-1; DESCRIPTOR_TABLE],
            });
            Self(PhantomData)
        }

        pub fn snapshot(&self) -> Counts {
            state(|state| state.counts).expect("observer armed")
        }

        /// Source-descriptor calls whose access mode was checked, by kind, since `begin_pass`.
        pub fn reach(&self) -> Reach {
            state(|state| state.reach).expect("observer armed")
        }

        /// The metadata calls of this pass in order (the first 256 of them), with the
        /// descriptor of an `fstat` (-1 for a path call).
        pub fn trace(&self) -> Vec<(Meta, c_int)> {
            state(|state| {
                state.trace[..state.trace_len]
                    .iter()
                    .map(|(which, fd)| (METAS[usize::from(*which)], *fd))
                    .collect()
            })
            .expect("observer armed")
        }

        /// Starts a new pass window. Streams still open stay held (the peak starts at them).
        pub fn begin_pass(&self) {
            state(|state| {
                state.counts = Counts {
                    held: state.counts.held,
                    peak: state.counts.held,
                    coverage_faults: state.counts.coverage_faults,
                    ..Counts::default()
                };
                state.reach = Reach::default();
                state.trace_len = 0;
            });
        }

        /// No stream, tracked descriptor or coverage fault remains.
        pub fn clean(&self) -> bool {
            state(|state| {
                state.counts.held == 0
                    && state.directories.iter().all(|entry| entry.0 == 0)
                    && state.descriptors.iter().all(|fd| *fd == -1)
                    && state.counts.coverage_faults == 0
            })
            .expect("observer armed")
        }
    }

    impl Drop for Observer {
        fn drop(&mut self) {
            *STATE
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        }
    }

    /// Metadata calls counted since the last `begin_pass`; 0 when nothing is armed. For other
    /// test-support code that must correlate its own events with the observer's work.
    pub fn metadata_so_far() -> u64 {
        state(|state| state.counts.metadata).unwrap_or(0)
    }

    /// Whether physical work stayed within every ceiling common to JSON and SQLite acquisition,
    /// with full coverage and no writable source descriptor. Raw read bytes are deliberately not
    /// part of it: the byte ceiling bounds materialized JSON only (see [`json_within`]); SQLite
    /// page reads are not a charged or bounded quantity.
    pub fn within(counts: Counts) -> bool {
        counts.coverage_faults == 0
            && counts.writable == 0
            && counts.metadata <= METADATA_CEILING
            && counts.opens <= OPEN_CEILING
            && counts.peak <= HELD_CEILING
            && counts.yields <= YIELD_CEILING
    }

    /// [`within`] plus the 64 MiB raw-read ceiling, for acquisition that reads only JSON files.
    pub fn json_within(counts: Counts) -> bool {
        within(counts) && counts.bytes <= JSON_BYTE_CEILING
    }
}
