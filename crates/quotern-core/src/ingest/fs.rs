use std::cell::RefCell;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use rusqlite::Connection;

use super::sqlite_ro::{self, OpenError};
use crate::domain::PassCounters;
use crate::limits::{MAX_METADATA_CALLS, MAX_OPEN_DIRECTORIES, MAX_PATH_BYTES};

pub type DirEntries = Box<dyn Iterator<Item = io::Result<PathBuf>> + Send>;

/// Open flags that `std` does not expose. The values are the kernel ABI constants of each
/// supported target; no new dependency is needed to name them.
#[cfg(target_os = "macos")]
pub(crate) mod open_flags {
    pub const NONBLOCK: i32 = 0x0004;
    pub const NOFOLLOW: i32 = 0x0100;
    pub const DIRECTORY: i32 = 0x0010_0000;
}

#[cfg(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "arm")))]
pub(crate) mod open_flags {
    pub const NONBLOCK: i32 = 0o4000;
    pub const NOFOLLOW: i32 = 0o100_000;
    pub const DIRECTORY: i32 = 0o40_000;
}

#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "aarch64", target_arch = "arm"))
))]
pub(crate) mod open_flags {
    pub const NONBLOCK: i32 = 0o4000;
    pub const NOFOLLOW: i32 = 0o400_000;
    pub const DIRECTORY: i32 = 0o200_000;
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("source acquisition requires the macOS or Linux open(2) ABI");

/// Identity and change witness of one opened file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileStamp {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub mtime_ns: i64,
}

impl FileStamp {
    pub fn of(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            mtime_ns: metadata
                .mtime()
                .saturating_mul(1_000_000_000)
                .saturating_add(metadata.mtime_nsec()),
        }
    }
}

#[derive(Debug)]
struct SelectedDirectoryLimit;

impl std::fmt::Display for SelectedDirectoryLimit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("selected directory scope limit exceeded")
    }
}

impl std::error::Error for SelectedDirectoryLimit {}

pub(crate) fn selected_directory_limit(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<SelectedDirectoryLimit>())
}

struct SelectedDirectory {
    path: PathBuf,
    stamp: FileStamp,
    witnessed: bool,
}

thread_local! {
    static SELECTED_DIRECTORIES: RefCell<[Option<SelectedDirectory>; MAX_OPEN_DIRECTORIES]> =
        const { RefCell::new([const { None }; MAX_OPEN_DIRECTORIES]) };
}

struct SelectedScope(usize);

impl SelectedScope {
    fn enter(path: &Path, stamp: FileStamp) -> io::Result<Self> {
        let valid = path.to_str().is_some_and(|text| {
            text.len() <= MAX_PATH_BYTES
                && !text.as_bytes().contains(&0)
                && text.starts_with('/')
                && (!text.contains("//")
                    && text
                        .split('/')
                        .skip(1)
                        .all(|part| part != "." && part != ".."))
        });
        if !valid {
            return Err(io::Error::other(SelectedDirectoryLimit));
        }
        SELECTED_DIRECTORIES.with(|scopes| {
            let mut scopes = scopes.borrow_mut();
            let index = scopes
                .iter()
                .position(Option::is_none)
                .ok_or_else(|| io::Error::other(SelectedDirectoryLimit))?;
            scopes[index] = Some(SelectedDirectory {
                path: path.to_path_buf(),
                stamp,
                witnessed: false,
            });
            Ok(Self(index))
        })
    }

    fn witnessed(&self) -> bool {
        SELECTED_DIRECTORIES.with(|scopes| {
            scopes.borrow()[self.0]
                .as_ref()
                .is_some_and(|scope| scope.witnessed)
        })
    }
}

impl Drop for SelectedScope {
    fn drop(&mut self) {
        SELECTED_DIRECTORIES.with(|scopes| scopes.borrow_mut()[self.0] = None);
    }
}

fn selected_attempt(path: &Path) -> Option<(usize, FileStamp)> {
    SELECTED_DIRECTORIES.with(|scopes| {
        let mut scopes = scopes.borrow_mut();
        let (index, scope) = scopes
            .iter_mut()
            .enumerate()
            .rev()
            .find_map(|(index, scope)| scope.as_mut().map(|scope| (index, scope)))?;
        if scope.path != path {
            return None;
        }
        scope.witnessed = false;
        Some((index, scope.stamp))
    })
}

fn selected_witness(index: usize) {
    SELECTED_DIRECTORIES.with(|scopes| {
        if let Some(scope) = scopes.borrow_mut()[index].as_mut() {
            scope.witnessed = true;
        }
    });
}

/// Bytes read through one descriptor plus its stamp before and after the read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedRead {
    pub bytes: Vec<u8>,
    pub before: FileStamp,
    pub after: FileStamp,
}

/// Raised when the per-pass metadata ceiling is reached: the operation about to run did not.
#[derive(Debug)]
struct BudgetExhausted {
    validation: bool,
}

impl std::fmt::Display for BudgetExhausted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("metadata budget exhausted")
    }
}

impl std::error::Error for BudgetExhausted {}

/// Whether `error` means the metadata ceiling ended the operation (resumable, not a failure).
pub fn budget_exhausted(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<BudgetExhausted>())
}

pub(crate) fn validation_budget_exhausted(error: &io::Error) -> bool {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<BudgetExhausted>())
        .is_some_and(|budget| budget.validation)
}

fn validation_budget(error: io::Error) -> io::Error {
    if budget_exhausted(&error) {
        io::Error::other(BudgetExhausted { validation: true })
    } else {
        error
    }
}

/// Charges one metadata-class operation (stat, fstat, lstat or readlink of a canonicalization
/// step) against the shared per-pass ceiling immediately before it runs.
pub fn charge_metadata(counters: &mut PassCounters) -> io::Result<()> {
    if counters.stat_calls >= MAX_METADATA_CALLS {
        return Err(io::Error::other(BudgetExhausted { validation: false }));
    }
    counters.stat_calls += 1;
    Ok(())
}

/// Physical filesystem operations performed on this thread, recorded at the single choke point
/// that issues each syscall (inside `RealSourceFs` and the read-only VFS), independently of the
/// pass counters that charge them.
#[cfg(feature = "test-faults")]
mod physical {
    use std::cell::Cell;

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct PhysicalOps {
        /// lstat, fstat and readlink calls.
        pub metadata: u64,
        /// Directory opens (one per held iterator).
        pub directory_opens: u64,
        /// Entries physically returned to a directory consumer.
        pub directory_yields: u64,
        /// Bytes physically requested from regular-file reads.
        pub bytes_requested: u64,
    }

    thread_local! {
        static OPERATIONS: Cell<PhysicalOps> = const { Cell::new(PhysicalOps {
            metadata: 0, directory_opens: 0, directory_yields: 0, bytes_requested: 0,
        }) };
    }

    fn update(change: impl FnOnce(&mut PhysicalOps)) {
        OPERATIONS.with(|operations| {
            let mut value = operations.get();
            change(&mut value);
            operations.set(value);
        });
    }

    pub fn tick() {
        update(|ops| ops.metadata += 1);
    }

    pub fn directory_open() {
        update(|ops| ops.directory_opens += 1);
    }

    pub fn directory_yield() {
        update(|ops| ops.directory_yields += 1);
    }

    pub fn bytes_requested(bytes: u64) {
        update(|ops| ops.bytes_requested += bytes);
    }

    pub fn operations() -> PhysicalOps {
        OPERATIONS.with(Cell::get)
    }
}

#[cfg(not(feature = "test-faults"))]
mod physical {
    #[inline]
    pub fn tick() {}
    #[inline]
    pub fn directory_open() {}
    #[inline]
    pub fn directory_yield() {}
    #[inline]
    pub fn bytes_requested(_bytes: u64) {}
}

pub(crate) use physical::tick;
#[cfg(feature = "test-faults")]
pub use physical::{PhysicalOps, operations as physical_operations};

/// Test control: one physical metadata call that no pass counter charged, so a test can prove
/// its physical-versus-charged oracle notices an uncharged operation.
#[cfg(feature = "test-faults")]
pub fn uncharged_metadata_call(path: &Path) {
    let _ = phys_lstat(path);
}

/// One physical `lstat`; the only place the acquisition code asks the kernel for path metadata.
fn phys_lstat(path: &Path) -> io::Result<Metadata> {
    tick();
    fs::symlink_metadata(path)
}

/// One physical `fstat` of an open descriptor.
fn phys_fstat(file: &File) -> io::Result<Metadata> {
    tick();
    file.metadata()
}

pub trait SourceFs {
    fn canonicalize(&self, path: &Path, counters: &mut PassCounters) -> io::Result<PathBuf>;
    fn metadata(&self, path: &Path, counters: &mut PassCounters) -> io::Result<Metadata>;
    fn read_dir(&self, path: &Path, counters: &mut PassCounters) -> io::Result<DirEntries>;
    /// Acquires the selected native directory descriptor. Providers must return its listing or
    /// lazily forward every entry, error and EOF in order, retaining the descriptor without
    /// filtering, prefetching, collecting or sorting. Providers without native proof fail closed.
    /// The canonical absolute UTF8 path is limited to 4096 bytes, with eight nested scopes per
    /// thread. Only device/inode bind the selection; directory contents are not a snapshot.
    fn read_dir_selected(
        &self,
        path: &Path,
        expected: FileStamp,
        counters: &mut PassCounters,
    ) -> io::Result<DirEntries> {
        let scope = SelectedScope::enter(path, expected)?;
        let entries = self.read_dir(path, counters)?;
        if !scope.witnessed() {
            return Err(io::Error::from(io::ErrorKind::Unsupported));
        }
        Ok(entries)
    }
    fn read_header(&self, path: &Path, counters: &mut PassCounters) -> io::Result<Vec<u8>>;
    fn read_bounded(
        &self,
        path: &Path,
        max_bytes: usize,
        counters: &mut PassCounters,
    ) -> io::Result<BoundedRead>;
    fn open_sqlite(&self, canonical_path: &Path) -> Result<Connection, OpenError>;

    /// Reads at most `max_bytes` of the opened file starting at `offset`: exactly
    /// `min(max_bytes, len - offset)` bytes (none at or past the end), with the file's stamp
    /// before and after the read. Metered like [`SourceFs::read_bounded`]. A filesystem that
    /// cannot serve tail reads keeps this default.
    fn read_tail(
        &self,
        path: &Path,
        offset: u64,
        max_bytes: usize,
        counters: &mut PassCounters,
    ) -> io::Result<BoundedRead> {
        let _ = (path, offset, max_bytes, counters);
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FsMetrics {
    pub entries: u64,
    /// Metadata-class operations physically performed: stat, fstat, canonicalize, ancestry probes.
    pub stat_calls: u64,
    pub header_reads: u64,
    pub directory_opens: u64,
    pub bounded_reads: u64,
    pub sqlite_opens: u64,
    pub tail_reads: u64,
    /// Directory iterators alive right now.
    pub open_directories: u64,
    /// Highest number of directory iterators alive at once.
    pub max_open_directories: u64,
}

fn changed(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, what)
}

type Meter<'a> = &'a mut dyn FnMut() -> io::Result<()>;

pub(crate) fn open_regular_with(path: &Path, meter: Meter<'_>) -> io::Result<(File, Metadata)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(open_flags::NOFOLLOW | open_flags::NONBLOCK)
        .open(path)?;
    meter()?;
    let metadata = phys_fstat(&file)?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "source path is not a regular file",
        ));
    }
    Ok((file, metadata))
}

/// Opens `path` without following a final symlink or blocking on a FIFO, and rejects anything that
/// is not a regular file. Returns the descriptor and its `fstat` metadata. Used where no pass
/// budget exists (the application store and read-only VFS paths that are metered elsewhere).
pub(crate) fn open_regular(path: &Path) -> io::Result<(File, Metadata)> {
    open_regular_with(path, &mut || Ok(()))
}

/// Resolves `path` exactly as `realpath` would, but one metered step at a time: every `lstat`
/// and `readlink` is charged immediately before the kernel is asked, so the physical metadata
/// work of a canonicalization is exactly what the pass was charged for.
fn canonicalize_metered(path: &Path, meter: Meter<'_>) -> io::Result<PathBuf> {
    use std::ffi::OsString;
    use std::path::Component;
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "source path is not absolute",
        ));
    }
    let components = |path: &Path| -> Vec<OsString> {
        path.components()
            .filter_map(|component| match component {
                Component::Normal(name) => Some(name.to_owned()),
                Component::ParentDir => Some(OsString::from("..")),
                _ => None,
            })
            .rev()
            .collect()
    };
    let mut pending = components(path);
    let mut resolved = PathBuf::from("/");
    let mut links = 0_u32;
    while let Some(name) = pending.pop() {
        if name == ".." {
            resolved.pop();
            continue;
        }
        resolved.push(&name);
        meter()?;
        let metadata = phys_lstat(&resolved)?;
        if metadata.file_type().is_symlink() {
            links += 1;
            if links > 40 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "too many symbolic links",
                ));
            }
            meter()?;
            tick();
            let target = fs::read_link(&resolved)?;
            resolved.pop();
            if target.is_absolute() {
                resolved = PathBuf::from("/");
            }
            pending.extend(components(&target));
        }
    }
    Ok(resolved)
}

/// Proves the pathname still names the descriptor's inode and has no symlinked ancestor.
fn verify_bound_with(path: &Path, opened: &Metadata, meter: Meter<'_>) -> io::Result<()> {
    if canonicalize_metered(path, meter)? != path {
        return Err(changed("source path ancestry changed"));
    }
    meter()?;
    let current = phys_lstat(path)?;
    if current.dev() != opened.dev() || current.ino() != opened.ino() {
        return Err(changed("source path was replaced"));
    }
    Ok(())
}

mod directory {
    use std::ffi::{OsStr, c_char, c_int, c_void};
    use std::io;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    #[cfg(target_os = "macos")]
    #[repr(C)]
    struct Dirent {
        ino: u64,
        seek_offset: u64,
        record_length: u16,
        name_length: u16,
        kind: u8,
        name: [c_char; 1024],
    }

    #[cfg(target_os = "linux")]
    #[repr(C)]
    struct Dirent {
        ino: u64,
        offset: i64,
        record_length: u16,
        kind: u8,
        name: [c_char; 256],
    }

    unsafe extern "C" {
        fn fdopendir(fd: c_int) -> *mut c_void;
        fn readdir(directory: *mut c_void) -> *mut Dirent;
        fn closedir(directory: *mut c_void) -> c_int;
        #[cfg(target_os = "macos")]
        fn __error() -> *mut c_int;
        #[cfg(target_os = "linux")]
        fn __errno_location() -> *mut c_int;
    }

    fn errno_slot() -> *mut c_int {
        // SAFETY: both functions return the calling thread's valid errno location.
        #[cfg(target_os = "macos")]
        unsafe {
            __error()
        }
        #[cfg(target_os = "linux")]
        unsafe {
            __errno_location()
        }
    }

    /// A directory iterator bound to the descriptor that was validated: entries come from that
    /// very handle, never from a second by-path open of the same name.
    pub struct HeldDirectory {
        stream: *mut c_void,
        path: PathBuf,
    }

    // SAFETY: the stream is owned exclusively by this value and only used through `&mut self`.
    unsafe impl Send for HeldDirectory {}

    impl HeldDirectory {
        /// Takes ownership of `handle`'s descriptor.
        pub fn new(handle: std::fs::File, path: PathBuf) -> io::Result<Self> {
            use std::os::fd::IntoRawFd;
            let fd = handle.into_raw_fd();
            // SAFETY: `fd` is an open directory descriptor now owned by the stream on success.
            let stream = unsafe { fdopendir(fd) };
            if stream.is_null() {
                let error = io::Error::last_os_error();
                // SAFETY: fdopendir failed, so the descriptor is still ours to close.
                drop(unsafe { std::fs::File::from_raw_fd(fd) });
                return Err(error);
            }
            Ok(Self { stream, path })
        }
    }

    impl Iterator for HeldDirectory {
        type Item = io::Result<PathBuf>;

        fn next(&mut self) -> Option<Self::Item> {
            loop {
                // SAFETY: errno is thread-local; clearing it distinguishes the end from an error.
                unsafe { *errno_slot() = 0 };
                // SAFETY: `stream` is a live directory stream.
                let entry = unsafe { readdir(self.stream) };
                if entry.is_null() {
                    // SAFETY: reading the thread-local errno.
                    let code = unsafe { *errno_slot() };
                    return (code != 0).then(|| Err(io::Error::from_raw_os_error(code)));
                }
                // SAFETY: readdir returned a valid entry whose name is NUL-terminated (and, on
                // macOS, `name_length` bytes long).
                let name = unsafe {
                    let entry = &*entry;
                    #[cfg(target_os = "macos")]
                    {
                        let length = usize::from(entry.name_length).min(entry.name.len());
                        std::slice::from_raw_parts(entry.name.as_ptr().cast::<u8>(), length)
                    }
                    #[cfg(target_os = "linux")]
                    {
                        std::ffi::CStr::from_ptr(entry.name.as_ptr()).to_bytes()
                    }
                };
                if name == b"." || name == b".." {
                    continue;
                }
                super::physical::directory_yield();
                return Some(Ok(self.path.join(OsStr::from_bytes(name))));
            }
        }
    }

    impl Drop for HeldDirectory {
        fn drop(&mut self) {
            // SAFETY: the stream is live and closed exactly once, releasing its descriptor.
            unsafe { closedir(self.stream) };
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RealSourceFs;

impl SourceFs for RealSourceFs {
    fn canonicalize(&self, path: &Path, counters: &mut PassCounters) -> io::Result<PathBuf> {
        canonicalize_metered(path, &mut || charge_metadata(counters))
    }

    fn metadata(&self, path: &Path, counters: &mut PassCounters) -> io::Result<Metadata> {
        charge_metadata(counters)?;
        phys_lstat(path)
    }

    fn read_dir(&self, path: &Path, counters: &mut PassCounters) -> io::Result<DirEntries> {
        let selected = selected_attempt(path);
        // One physical open: the iterator is created from this validated handle.
        let handle = OpenOptions::new()
            .read(true)
            .custom_flags(open_flags::NOFOLLOW | open_flags::NONBLOCK | open_flags::DIRECTORY)
            .open(path)?;
        physical::directory_open();
        charge_metadata(counters).map_err(validation_budget)?;
        let opened = phys_fstat(&handle)?;
        if !opened.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source path is not a directory",
            ));
        }
        if let Some((_, expected)) = selected
            && (opened.dev() != expected.device || opened.ino() != expected.inode)
        {
            return Err(changed("selected directory changed"));
        }
        verify_bound_with(path, &opened, &mut || charge_metadata(counters))
            .map_err(validation_budget)?;
        let entries = Box::new(directory::HeldDirectory::new(handle, path.to_path_buf())?);
        if let Some((index, _)) = selected {
            selected_witness(index);
        }
        Ok(entries)
    }

    fn read_header(&self, path: &Path, counters: &mut PassCounters) -> io::Result<Vec<u8>> {
        let (file, opened) = open_regular_with(path, &mut || charge_metadata(counters))?;
        verify_bound_with(path, &opened, &mut || charge_metadata(counters))?;
        let mut header = Vec::with_capacity(100);
        physical::bytes_requested(100);
        file.take(100).read_to_end(&mut header)?;
        Ok(header)
    }

    /// Reads exactly the opened file's bytes, which must fit `max_bytes`: an oversized file is
    /// reported by its stamp without a single content byte being requested, and a file that
    /// grows after the open is caught by the stamp taken after the read, never by an extra
    /// sentinel byte.
    fn read_bounded(
        &self,
        path: &Path,
        max_bytes: usize,
        counters: &mut PassCounters,
    ) -> io::Result<BoundedRead> {
        let (file, opened) = open_regular_with(path, &mut || charge_metadata(counters))?;
        verify_bound_with(path, &opened, &mut || charge_metadata(counters))?;
        let wanted = if opened.len() <= max_bytes as u64 {
            opened.len()
        } else {
            0
        };
        let mut bytes = Vec::with_capacity(usize::try_from(wanted).unwrap_or(0));
        physical::bytes_requested(wanted);
        (&file).take(wanted).read_to_end(&mut bytes)?;
        charge_metadata(counters)?;
        let after = phys_fstat(&file)?;
        Ok(BoundedRead {
            bytes,
            before: FileStamp::of(&opened),
            after: FileStamp::of(&after),
        })
    }

    fn open_sqlite(&self, canonical_path: &Path) -> Result<Connection, OpenError> {
        sqlite_ro::open_canonical(canonical_path)
    }

    fn read_tail(
        &self,
        path: &Path,
        offset: u64,
        max_bytes: usize,
        counters: &mut PassCounters,
    ) -> io::Result<BoundedRead> {
        read_tail_with(path, offset, max_bytes, counters, || {})
    }
}

fn read_tail_with(
    path: &Path,
    offset: u64,
    max_bytes: usize,
    counters: &mut PassCounters,
    after_read: impl FnOnce(),
) -> io::Result<BoundedRead> {
    let (mut file, opened) = open_regular_with(path, &mut || charge_metadata(counters))?;
    verify_bound_with(path, &opened, &mut || charge_metadata(counters))?;
    let wanted = opened
        .len()
        .saturating_sub(offset)
        .min(u64::try_from(max_bytes).unwrap_or(u64::MAX));
    let mut bytes = Vec::with_capacity(usize::try_from(wanted).unwrap_or(0));
    physical::bytes_requested(wanted);
    if wanted > 0 {
        file.seek(SeekFrom::Start(offset))?;
        if let Err(error) = (&file).take(wanted).read_to_end(&mut bytes) {
            counters.bytes_read = counters.bytes_read.saturating_add(bytes.len() as u64);
            return Err(error);
        }
    }
    after_read();
    let proof = (|| {
        charge_metadata(counters)?;
        let after = phys_fstat(&file)?;
        verify_bound_with(path, &opened, &mut || charge_metadata(counters))?;
        Ok(after)
    })();
    let after = match proof {
        Ok(after) => after,
        Err(error) => {
            counters.bytes_read = counters.bytes_read.saturating_add(bytes.len() as u64);
            return Err(error);
        }
    };
    Ok(BoundedRead {
        bytes,
        before: FileStamp::of(&opened),
        after: FileStamp::of(&after),
    })
}

#[cfg(feature = "test-faults")]
mod recording {
    use std::io;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use rusqlite::Connection;

    use super::{BoundedRead, DirEntries, FsMetrics, RealSourceFs, SourceFs, physical_operations};
    use crate::domain::PassCounters;
    use crate::ingest::sqlite_ro::OpenError;

    /// Operation about to touch the filesystem; passed to the test boundary hook.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum OpenKind {
        Header,
        Bounded,
        Directory,
        Sqlite,
        Tail,
        TailRead,
    }

    type BoundaryHook = Box<dyn FnMut(OpenKind, &Path) + Send>;

    #[derive(Default)]
    struct Calls {
        entries: AtomicU64,
        stat_calls: AtomicU64,
        header_reads: AtomicU64,
        directory_opens: AtomicU64,
        bounded_reads: AtomicU64,
        sqlite_opens: AtomicU64,
        tail_reads: AtomicU64,
        open_directories: AtomicU64,
        max_open_directories: AtomicU64,
        hook: Mutex<Option<BoundaryHook>>,
    }

    #[derive(Clone)]
    pub struct RecordingFs {
        inner: RealSourceFs,
        calls: Arc<Calls>,
    }

    impl Default for RecordingFs {
        fn default() -> Self {
            Self::new()
        }
    }

    struct HeldDirectory {
        entries: DirEntries,
        calls: Arc<Calls>,
    }

    impl Iterator for HeldDirectory {
        type Item = io::Result<PathBuf>;

        fn next(&mut self) -> Option<Self::Item> {
            let entry = self.entries.next();
            if entry.is_some() {
                self.calls.entries.fetch_add(1, Ordering::Relaxed);
            }
            entry
        }
    }

    impl Drop for HeldDirectory {
        fn drop(&mut self) {
            self.calls.open_directories.fetch_sub(1, Ordering::Relaxed);
        }
    }

    impl RecordingFs {
        pub fn new() -> Self {
            Self {
                inner: RealSourceFs,
                calls: Arc::new(Calls::default()),
            }
        }

        /// Runs `hook` after the operation is counted and before it touches the filesystem, so a
        /// test can replace the path at exactly that boundary.
        pub fn on_boundary(&self, hook: impl FnMut(OpenKind, &Path) + Send + 'static) {
            if let Ok(mut slot) = self.calls.hook.lock() {
                *slot = Some(Box::new(hook));
            }
        }

        pub fn metrics(&self) -> FsMetrics {
            use Ordering::Relaxed;
            FsMetrics {
                entries: self.calls.entries.load(Relaxed),
                stat_calls: self.calls.stat_calls.load(Relaxed),
                header_reads: self.calls.header_reads.load(Relaxed),
                directory_opens: self.calls.directory_opens.load(Relaxed),
                bounded_reads: self.calls.bounded_reads.load(Relaxed),
                sqlite_opens: self.calls.sqlite_opens.load(Relaxed),
                tail_reads: self.calls.tail_reads.load(Relaxed),
                open_directories: self.calls.open_directories.load(Relaxed),
                max_open_directories: self.calls.max_open_directories.load(Relaxed),
            }
        }

        fn boundary(&self, kind: OpenKind, path: &Path) {
            if let Ok(mut slot) = self.calls.hook.lock()
                && let Some(hook) = slot.as_mut()
            {
                hook(kind, path);
            }
        }
    }

    impl RecordingFs {
        /// Runs `call` and attributes the physical metadata-class operations it performed.
        fn measured<T>(&self, call: impl FnOnce() -> T) -> T {
            let before = physical_operations().metadata;
            let result = call();
            self.calls.stat_calls.fetch_add(
                physical_operations().metadata.saturating_sub(before),
                Ordering::Relaxed,
            );
            result
        }
    }

    impl SourceFs for RecordingFs {
        fn canonicalize(&self, path: &Path, counters: &mut PassCounters) -> io::Result<PathBuf> {
            self.measured(|| self.inner.canonicalize(path, counters))
        }

        fn metadata(
            &self,
            path: &Path,
            counters: &mut PassCounters,
        ) -> io::Result<std::fs::Metadata> {
            self.measured(|| self.inner.metadata(path, counters))
        }

        fn read_dir(&self, path: &Path, counters: &mut PassCounters) -> io::Result<DirEntries> {
            super::selected_attempt(path);
            self.calls.directory_opens.fetch_add(1, Ordering::Relaxed);
            self.boundary(OpenKind::Directory, path);
            let entries = self.measured(|| self.inner.read_dir(path, counters))?;
            let open = self.calls.open_directories.fetch_add(1, Ordering::Relaxed) + 1;
            self.calls
                .max_open_directories
                .fetch_max(open, Ordering::Relaxed);
            Ok(Box::new(HeldDirectory {
                entries,
                calls: Arc::clone(&self.calls),
            }))
        }

        fn read_header(&self, path: &Path, counters: &mut PassCounters) -> io::Result<Vec<u8>> {
            self.calls.header_reads.fetch_add(1, Ordering::Relaxed);
            self.boundary(OpenKind::Header, path);
            self.measured(|| self.inner.read_header(path, counters))
        }

        fn read_bounded(
            &self,
            path: &Path,
            max_bytes: usize,
            counters: &mut PassCounters,
        ) -> io::Result<BoundedRead> {
            self.calls.bounded_reads.fetch_add(1, Ordering::Relaxed);
            self.boundary(OpenKind::Bounded, path);
            self.measured(|| self.inner.read_bounded(path, max_bytes, counters))
        }

        fn open_sqlite(&self, path: &Path) -> Result<Connection, OpenError> {
            self.calls.sqlite_opens.fetch_add(1, Ordering::Relaxed);
            self.boundary(OpenKind::Sqlite, path);
            self.measured(|| self.inner.open_sqlite(path))
        }

        fn read_tail(
            &self,
            path: &Path,
            offset: u64,
            max_bytes: usize,
            counters: &mut PassCounters,
        ) -> io::Result<BoundedRead> {
            self.calls.tail_reads.fetch_add(1, Ordering::Relaxed);
            self.boundary(OpenKind::Tail, path);
            self.measured(|| {
                super::read_tail_with(path, offset, max_bytes, counters, || {
                    self.boundary(OpenKind::TailRead, path)
                })
            })
        }
    }
}

#[cfg(feature = "test-faults")]
pub use recording::{OpenKind, RecordingFs};
