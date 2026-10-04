use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};
use std::ffi::{CStr, CString, OsString, c_char, c_int, c_uint, c_void};
use std::fs::{File, Metadata};
use std::io;
use std::mem::{ManuallyDrop, size_of};
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex, OnceLock};
use std::time::{Duration, Instant};

use rusqlite::ffi;
use rusqlite::{Connection, OpenFlags};

use crate::domain::{FailureCode, PassCounters};
use crate::ingest::fs::{SourceFs, budget_exhausted, open_regular_with, tick};
use crate::limits::{
    MAX_HEADER_READS, MAX_PATH_BYTES, SQLITE_BUSY_TIMEOUT_MS, SQLITE_PROGRESS_INTERVAL,
};

const VFS_NAME: &[u8] = b"quotern-ro\0";
const WRITE_FLAGS: c_int =
    ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_CREATE | ffi::SQLITE_OPEN_DELETEONCLOSE;
const FILE_TYPE_MASK: c_int = 0x000F_FF00;
const IOERR_READ: c_int = ffi::SQLITE_IOERR | (1 << 8);
const IOERR_SHORT_READ: c_int = ffi::SQLITE_IOERR | (2 << 8);
const IOERR_SHMMAP: c_int = ffi::SQLITE_IOERR | (21 << 8);
const PROT_WRITE: c_int = 2;
const F_GETFL: c_int = 3;
const O_ACCMODE: c_int = 3;
const O_RDONLY: c_int = 0;

unsafe extern "C" {
    fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
}

/// The failure value of a call this module refuses before it reaches the kernel. `errno` is set
/// here, to `EBADF` through a query of an invalid descriptor that changes nothing: a refusal
/// leaves whatever an earlier call left, and SQLite's `robust_open` retries an `open` that fails
/// with `EINTR` without bound, so a stale `EINTR` behind a refused open would never end.
fn refuse() -> c_int {
    // SAFETY: F_GETFL on an invalid descriptor only fails.
    unsafe { fcntl(-1, F_GETFL) };
    -1
}

static REGISTERED_VFS: LazyLock<Result<RegisteredVfs, c_int>> = LazyLock::new(register_vfs);

// ---------------------------------------------------------------------------------------------
// Process-wide observation of the pinned Unix parent's syscalls.
//
// The parent VFS is SQLite's own "unix" implementation. Its `fchmod`, `fchown`, `fstat`, `mmap`
// and `munmap` entries are interposed through the documented `xSetSystemCall` interface. Outside
// a source scope every hook forwards unchanged, so the application's own store is unaffected.
// Inside a scope (any call made on behalf of a source file) they enforce and record:
//   * `fchmod`/`fchown` never reach the kernel, so an open cannot change source metadata;
//   * every descriptor the parent inspects must be a regular file opened read-only, which is
//     checked with the kernel's own `F_GETFL`, independently of the flags this VFS passed;
//   * every shared-memory mapping is recorded with its protection, so a mapping inherited from a
//     writable in-process connection (or one this VFS never saw) is detected and refused.
// ---------------------------------------------------------------------------------------------

type StatFn = unsafe extern "C" fn(*const c_char, *mut c_void) -> c_int;
type ReadlinkFn = unsafe extern "C" fn(*const c_char, *mut c_char, usize) -> isize;
type AccessFn = unsafe extern "C" fn(*const c_char, c_int) -> c_int;
type OpenFn = unsafe extern "C" fn(*const c_char, c_int, c_int) -> c_int;
type FchmodFn = unsafe extern "C" fn(c_int, c_uint) -> c_int;
type FchownFn = unsafe extern "C" fn(c_int, c_uint, c_uint) -> c_int;
type FstatFn = unsafe extern "C" fn(c_int, *mut c_void) -> c_int;
type MmapFn = unsafe extern "C" fn(*mut c_void, usize, c_int, c_int, c_int, i64) -> *mut c_void;
type MunmapFn = unsafe extern "C" fn(*mut c_void, usize) -> c_int;

struct Originals {
    open: OpenFn,
    stat: StatFn,
    lstat: StatFn,
    readlink: ReadlinkFn,
    access: AccessFn,
    fchmod: Option<FchmodFn>,
    fchown: Option<FchownFn>,
    fstat: FstatFn,
    mmap: MmapFn,
    munmap: MunmapFn,
}

// The original entries exist only at run time, read from the pinned parent VFS's syscall table.
static ORIGINALS: OnceLock<Originals> = OnceLock::new();
/// What this process knows of one mapping the pinned parent made: its length, whether it was
/// requested writable, and the (device, inode) the descriptor named, taken from the `fstat` the
/// parent issued on that descriptor right before the `mmap` (`None`: no such `fstat` was seen, so
/// the mapping cannot be bound to a file).
#[derive(Clone, Copy)]
struct MapRecord {
    length: usize,
    writable: bool,
    identity: Option<(u64, u64)>,
}

static MAPS: Mutex<BTreeMap<usize, MapRecord>> = Mutex::new(BTreeMap::new());

struct HookStats {
    metadata_effects_blocked: AtomicUsize,
    descriptors_verified: AtomicUsize,
    writable_descriptors: AtomicUsize,
    nonregular_descriptors: AtomicUsize,
    readonly_maps: AtomicUsize,
    writable_maps_rejected: AtomicUsize,
    unverified_maps_rejected: AtomicUsize,
    opens_verified: AtomicUsize,
    opens_refused: AtomicUsize,
    identity_rejected: AtomicUsize,
}

static HOOK_STATS: HookStats = HookStats {
    metadata_effects_blocked: AtomicUsize::new(0),
    descriptors_verified: AtomicUsize::new(0),
    writable_descriptors: AtomicUsize::new(0),
    nonregular_descriptors: AtomicUsize::new(0),
    readonly_maps: AtomicUsize::new(0),
    writable_maps_rejected: AtomicUsize::new(0),
    unverified_maps_rejected: AtomicUsize::new(0),
    identity_rejected: AtomicUsize::new(0),
    opens_verified: AtomicUsize::new(0),
    opens_refused: AtomicUsize::new(0),
};

/// A path the next delegated open must name by exactly this inode (`None`: it must not exist).
struct Expectation {
    path: Vec<u8>,
    identity: Option<(u64, u64)>,
    matched: bool,
}

/// The application store's database, whose by-name open must land on the bound inode.
struct StoreBinding {
    path: Vec<u8>,
    identity: (u64, u64),
    main_matched: bool,
    refused: bool,
}

/// Metadata-class operations the read-only VFS and its pinned parent may still perform for the
/// current source read; consumed physically, before each operation, never as a fixed estimate.
#[derive(Clone, Copy)]
struct MeterState {
    allowance: u32,
    used: u32,
    refused: bool,
}

thread_local! {
    static SCOPE: Cell<u32> = const { Cell::new(0) };
    static WORK: Cell<Option<WorkLimit>> = const { Cell::new(None) };
    static EXPECTATIONS: RefCell<Vec<Expectation>> = const { RefCell::new(Vec::new()) };
    static STORE_BINDING: RefCell<Option<StoreBinding>> = const { RefCell::new(None) };
    static METER: Cell<Option<MeterState>> = const { Cell::new(None) };
    static PENDING_OVERLAY: RefCell<Option<Box<WalOverlay>>> = const { RefCell::new(None) };
    /// Descriptor and identity of the last `fstat` the pinned parent completed on this thread.
    static LAST_FSTAT: Cell<Option<(c_int, (u64, u64))>> = const { Cell::new(None) };
}

/// Guard that meters the metadata-class operations of the VFS on this thread. Without a guard
/// (the application store, direct readers) the VFS is unmetered.
pub struct MetadataMeter(());

impl MetadataMeter {
    pub fn begin(allowance: u32) -> Self {
        METER.with(|meter| {
            meter.set(Some(MeterState {
                allowance,
                used: 0,
                refused: false,
            }));
        });
        Self(())
    }

    /// Operations performed so far, and whether one was refused for lack of allowance.
    pub fn state(&self) -> (u32, bool) {
        METER.with(|meter| meter.get().map_or((0, false), |m| (m.used, m.refused)))
    }
}

impl Drop for MetadataMeter {
    fn drop(&mut self) {
        METER.with(|meter| meter.set(None));
    }
}

/// Charges one physical metadata-class operation immediately before it runs. `false`: the
/// allowance is spent and the operation must not run.
fn charge() -> bool {
    METER.with(|meter| match meter.get() {
        None => true,
        Some(mut state) if state.used < state.allowance => {
            state.used += 1;
            meter.set(Some(state));
            true
        }
        Some(mut state) => {
            state.refused = true;
            meter.set(Some(state));
            false
        }
    })
}

/// Gives back one [`charge`] whose operation never ran, so `used` stays the physical count. Only
/// thread-local state is touched: `errno` is left as the failed call set it.
fn uncharge() {
    METER.with(|meter| {
        if let Some(mut state) = meter.get() {
            state.used = state.used.saturating_sub(1);
            meter.set(Some(state));
        }
    });
}

fn charge_io() -> io::Result<()> {
    if charge() {
        Ok(())
    } else {
        Err(io::Error::other("metadata budget exhausted"))
    }
}

/// A test boundary callback invoked with the path about to be opened.
#[cfg(feature = "test-faults")]
pub type OpenHook = Box<dyn FnMut(&Path)>;

#[cfg(feature = "test-faults")]
thread_local! {
    static OPEN_HOOK: RefCell<Option<OpenHook>> = const { RefCell::new(None) };
}

/// Test boundary: runs `hook` with the path of every by-name open the parent VFS is about to
/// make for a source file or the bound store, immediately before the kernel `open`, so a test
/// can swap the path at exactly that instant.
#[cfg(feature = "test-faults")]
pub fn set_open_hook(hook: Option<OpenHook>) {
    OPEN_HOOK.with(|slot| *slot.borrow_mut() = hook);
}

#[cfg(feature = "test-faults")]
fn run_open_hook(name: &[u8]) {
    let taken = OPEN_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(mut hook) = taken {
        hook(Path::new(std::ffi::OsStr::from_bytes(name)));
        OPEN_HOOK.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.is_none() {
                *slot = Some(hook);
            }
        });
    }
}

/// RAII registration of an [`Expectation`] for the duration of one delegated open.
struct ExpectGuard {
    path: Vec<u8>,
}

impl ExpectGuard {
    fn register(path: Vec<u8>, identity: Option<(u64, u64)>) -> Self {
        EXPECTATIONS.with(|list| {
            list.borrow_mut().push(Expectation {
                path: path.clone(),
                identity,
                matched: false,
            });
        });
        Self { path }
    }

    /// Whether the open of this path was seen by the kernel-level hook and named the expected
    /// inode.
    fn matched(&self) -> bool {
        EXPECTATIONS.with(|list| {
            list.borrow()
                .iter()
                .any(|entry| entry.path == self.path && entry.matched)
        })
    }
}

impl Drop for ExpectGuard {
    fn drop(&mut self) {
        EXPECTATIONS.with(|list| list.borrow_mut().retain(|entry| entry.path != self.path));
    }
}

/// Binds the application store's database path to the inode already validated through its
/// directory handle: the parent VFS's by-name open of exactly that path is refused unless the
/// descriptor it obtained is that inode. Sidecars must be regular, unaliased and on the same
/// device. Active only on the creating thread, only while the guard lives.
pub struct StoreBind(());

pub fn bind_store(database: &Path, identity: (u64, u64)) -> Result<StoreBind, OpenError> {
    vfs_name()?;
    STORE_BINDING.with(|slot| {
        *slot.borrow_mut() = Some(StoreBinding {
            path: database.as_os_str().as_bytes().to_vec(),
            identity,
            main_matched: false,
            refused: false,
        });
    });
    Ok(StoreBind(()))
}

impl StoreBind {
    /// The parent opened the main database and it was the bound inode.
    pub fn main_verified(&self) -> bool {
        STORE_BINDING.with(|slot| slot.borrow().as_ref().is_some_and(|b| b.main_matched))
    }

    /// Some open was refused because it did not name the bound inode or was an alias.
    pub fn refused(&self) -> bool {
        STORE_BINDING.with(|slot| slot.borrow().as_ref().is_some_and(|b| b.refused))
    }
}

impl Drop for StoreBind {
    fn drop(&mut self) {
        STORE_BINDING.with(|slot| *slot.borrow_mut() = None);
    }
}

unsafe extern "C" {
    fn close(fd: c_int) -> c_int;
}

/// Kernel-level view of a freshly opened descriptor: the `open` entry of the pinned parent is
/// interposed, so the descriptor SQLite actually holds is checked, not the path it was asked for.
unsafe extern "C" fn hook_open(path: *const c_char, flags: c_int, mode: c_int) -> c_int {
    let Some(originals) = ORIGINALS.get() else {
        return -1;
    };
    let source = in_source_scope();
    let bound = !source && STORE_BINDING.with(|slot| slot.borrow().is_some());
    if !source && !bound {
        return unsafe { (originals.open)(path, flags, mode) };
    }
    let name = unsafe { CStr::from_ptr(path) }.to_bytes();
    #[cfg(feature = "test-faults")]
    run_open_hook(name);
    let (flags, mode) = if source {
        // A source file is never created, truncated, written or waited on: read-only,
        // non-blocking, whatever the parent asked for.
        if !charge() {
            return refuse();
        }
        (
            (flags & !(create_flags::CREAT | create_flags::TRUNC | create_flags::EXCL | O_ACCMODE))
                | O_RDONLY
                | crate::ingest::fs::open_flags::NONBLOCK,
            0,
        )
    } else {
        (flags, mode)
    };
    let fd = unsafe { (originals.open)(path, flags, mode) };
    if fd < 0 {
        // The charge above reserved the validation `fstat` of a descriptor; there is none, so no
        // metadata operation happened and the reservation goes back.
        if source {
            uncharge();
        }
        return fd;
    }
    // SAFETY: `fd` was just returned by the parent's open and is not closed here on success.
    let file = ManuallyDrop::new(unsafe { File::from_raw_fd(fd) });
    tick();
    let metadata = file.metadata().ok();
    let accepted = match &metadata {
        None => false,
        Some(metadata) if source => {
            metadata.is_file()
                && EXPECTATIONS.with(|list| {
                    let mut list = list.borrow_mut();
                    match list.iter_mut().find(|entry| entry.path == name) {
                        None => true,
                        Some(entry) => {
                            let same = entry.identity == Some((metadata.dev(), metadata.ino()));
                            entry.matched |= same;
                            same
                        }
                    }
                })
        }
        Some(metadata) => STORE_BINDING.with(|slot| {
            let mut slot = slot.borrow_mut();
            let Some(binding) = slot.as_mut() else {
                return true;
            };
            let is_main = name == binding.path.as_slice();
            let is_sidecar = ["-wal", "-shm", "-journal"].iter().any(|suffix| {
                name.strip_prefix(binding.path.as_slice())
                    .is_some_and(|rest| rest == suffix.as_bytes())
            });
            let accepted = if is_main {
                let same = (metadata.dev(), metadata.ino()) == binding.identity;
                binding.main_matched |= same;
                same && metadata.is_file() && metadata.nlink() == 1
            } else if is_sidecar {
                metadata.is_file() && metadata.nlink() == 1 && metadata.dev() == binding.identity.0
            } else {
                true
            };
            binding.refused |= !accepted;
            accepted
        }),
    };
    if !accepted {
        HOOK_STATS.opens_refused.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the descriptor is ours (returned above) and closed exactly once.
        unsafe { close(fd) };
        return refuse();
    }
    HOOK_STATS.opens_verified.fetch_add(1, Ordering::Relaxed);
    fd
}

/// RAII marker: syscalls made on this thread while it is alive belong to a source file.
struct Scope;

impl Scope {
    fn enter() -> Self {
        SCOPE.with(|scope| scope.set(scope.get() + 1));
        Self
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        SCOPE.with(|scope| scope.set(scope.get().saturating_sub(1)));
    }
}

fn in_source_scope() -> bool {
    SCOPE.with(|scope| scope.get() > 0)
}

unsafe extern "C" fn hook_fchmod(fd: c_int, mode: c_uint) -> c_int {
    if in_source_scope() {
        HOOK_STATS
            .metadata_effects_blocked
            .fetch_add(1, Ordering::Relaxed);
        return refuse();
    }
    match ORIGINALS.get().and_then(|originals| originals.fchmod) {
        Some(original) => unsafe { original(fd, mode) },
        None => -1,
    }
}

unsafe extern "C" fn hook_fchown(fd: c_int, user: c_uint, group: c_uint) -> c_int {
    if in_source_scope() {
        HOOK_STATS
            .metadata_effects_blocked
            .fetch_add(1, Ordering::Relaxed);
        return refuse();
    }
    match ORIGINALS.get().and_then(|originals| originals.fchown) {
        Some(original) => unsafe { original(fd, user, group) },
        None => -1,
    }
}

unsafe extern "C" fn hook_fstat(fd: c_int, buffer: *mut c_void) -> c_int {
    let Some(originals) = ORIGINALS.get() else {
        return -1;
    };
    let source = in_source_scope();
    if source {
        // Every fstat the parent issues for a source file is charged before the kernel runs it.
        if !charge() {
            return refuse();
        }
        tick();
    }
    let result = unsafe { (originals.fstat)(fd, buffer) };
    // SAFETY: the kernel just filled `buffer` with the `struct stat` of `fd` when it succeeded.
    let identity = (result == 0).then(|| (fd, unsafe { stat_identity(buffer) }));
    LAST_FSTAT.with(|last| last.set(identity));
    if result != 0 || !source {
        return result;
    }
    // The regular-file check is a second physical `fstat` of the same descriptor: it is charged
    // and counted like the first, never performed for free.
    if !charge() {
        return refuse();
    }
    tick();
    // SAFETY: `fd` is a live descriptor owned by the parent VFS; ManuallyDrop keeps it open.
    let file = ManuallyDrop::new(unsafe { File::from_raw_fd(fd) });
    let regular = file.metadata().is_ok_and(|metadata| metadata.is_file());
    let flags = unsafe { fcntl(fd, F_GETFL) };
    if !regular {
        HOOK_STATS
            .nonregular_descriptors
            .fetch_add(1, Ordering::Relaxed);
        return refuse();
    }
    if flags < 0 || flags & O_ACCMODE != O_RDONLY {
        HOOK_STATS
            .writable_descriptors
            .fetch_add(1, Ordering::Relaxed);
        return refuse();
    }
    HOOK_STATS
        .descriptors_verified
        .fetch_add(1, Ordering::Relaxed);
    result
}

unsafe extern "C" fn hook_mmap(
    address: *mut c_void,
    length: usize,
    protection: c_int,
    flags: c_int,
    fd: c_int,
    offset: i64,
) -> *mut c_void {
    let Some(originals) = ORIGINALS.get() else {
        return usize::MAX as *mut c_void;
    };
    let mapped = unsafe { (originals.mmap)(address, length, protection, flags, fd, offset) };
    if mapped as usize != usize::MAX
        && let Ok(mut maps) = MAPS.lock()
    {
        // The SQLite Unix parent issues an `fstat` of the very descriptor right before it maps
        // (`unixShmMap`, `unixMapfile`); the identity that `fstat` reported is what the mapping
        // belongs to. Without such an `fstat` the mapping stays unbound.
        let identity = LAST_FSTAT
            .with(Cell::get)
            .filter(|(last, _)| *last == fd)
            .map(|(_, identity)| identity);
        maps.insert(
            mapped as usize,
            MapRecord {
                length,
                writable: protection & PROT_WRITE != 0,
                identity,
            },
        );
    }
    mapped
}

unsafe extern "C" fn hook_munmap(address: *mut c_void, length: usize) -> c_int {
    let Some(originals) = ORIGINALS.get() else {
        return -1;
    };
    let result = unsafe { (originals.munmap)(address, length) };
    if result == 0
        && let Ok(mut maps) = MAPS.lock()
    {
        maps.remove(&(address as usize));
    }
    result
}

/// What this process observed of the mapping that contains `pointer`; `None` when it never saw
/// the mapping (it predates the hooks or came from another allocator).
fn mapping_of(pointer: *mut c_void) -> Option<MapRecord> {
    let address = pointer as usize;
    let maps = MAPS.lock().ok()?;
    let (start, record) = maps.range(..=address).next_back()?;
    (address < start.checked_add(record.length)?).then_some(*record)
}

/// Path-based metadata the parent issues on behalf of a source read (`xFullPathname` walks the
/// path with `lstat`/`readlink`, `xAccess` stats it): each is charged before the kernel runs it.
unsafe extern "C" fn hook_stat(path: *const c_char, buffer: *mut c_void) -> c_int {
    let Some(originals) = ORIGINALS.get() else {
        return -1;
    };
    if in_source_scope() {
        if !charge() {
            return refuse();
        }
        tick();
    }
    let result = unsafe { (originals.stat)(path, buffer) };
    if result != 0 {
        return result;
    }
    if !in_source_scope() {
        // The writable store: a by-name `stat` of its database path (the parent keys fd reuse on
        // it) must name the bound inode, exactly like the open itself.
        let name = unsafe { CStr::from_ptr(path) }.to_bytes();
        let identity = unsafe { stat_identity(buffer) };
        let accepted = STORE_BINDING.with(|slot| {
            let mut slot = slot.borrow_mut();
            match slot.as_mut() {
                Some(binding) if name == binding.path.as_slice() => {
                    let same = identity == binding.identity;
                    binding.main_matched |= same;
                    binding.refused |= !same;
                    same
                }
                _ => true,
            }
        });
        return if accepted { result } else { refuse() };
    }
    // The parent may reuse a descriptor it already holds for the inode this name resolves to
    // (no `open` then): the by-name `stat` it keys that reuse on must therefore name exactly the
    // inode that was probed.
    let name = unsafe { CStr::from_ptr(path) }.to_bytes();
    let identity = unsafe { stat_identity(buffer) };
    let accepted = EXPECTATIONS.with(|list| {
        let mut list = list.borrow_mut();
        match list.iter_mut().find(|entry| entry.path == name) {
            None => true,
            Some(entry) => {
                let same = entry.identity == Some(identity);
                entry.matched |= same;
                same
            }
        }
    });
    if accepted {
        result
    } else {
        HOOK_STATS.opens_refused.fetch_add(1, Ordering::Relaxed);
        refuse()
    }
}

/// Device and inode of a `struct stat` the kernel just filled (the fields every supported
/// target places first: device at 0, inode at 8).
unsafe fn stat_identity(buffer: *const c_void) -> (u64, u64) {
    let bytes = buffer.cast::<u8>();
    // SAFETY: the caller passes a `struct stat` that stat(2) filled successfully.
    unsafe {
        #[cfg(target_os = "macos")]
        let device = i64::from(i32::from_ne_bytes(bytes.cast::<[u8; 4]>().read())) as u64;
        #[cfg(target_os = "linux")]
        let device = u64::from_ne_bytes(bytes.cast::<[u8; 8]>().read());
        let inode = u64::from_ne_bytes(bytes.add(8).cast::<[u8; 8]>().read());
        (device, inode)
    }
}

unsafe extern "C" fn hook_lstat(path: *const c_char, buffer: *mut c_void) -> c_int {
    let Some(originals) = ORIGINALS.get() else {
        return -1;
    };
    if in_source_scope() {
        if !charge() {
            return refuse();
        }
        tick();
    }
    unsafe { (originals.lstat)(path, buffer) }
}

unsafe extern "C" fn hook_readlink(path: *const c_char, buffer: *mut c_char, size: usize) -> isize {
    let Some(originals) = ORIGINALS.get() else {
        return -1;
    };
    if in_source_scope() {
        if !charge() {
            return refuse() as isize;
        }
        tick();
    }
    unsafe { (originals.readlink)(path, buffer, size) }
}

unsafe extern "C" fn hook_access(path: *const c_char, mode: c_int) -> c_int {
    let Some(originals) = ORIGINALS.get() else {
        return -1;
    };
    if in_source_scope() {
        if !charge() {
            return refuse();
        }
        tick();
    }
    unsafe { (originals.access)(path, mode) }
}

unsafe fn install_hooks(parent: NonNull<ffi::sqlite3_vfs>) -> Result<(), c_int> {
    let parent = parent.as_ptr();
    let get = unsafe { (*parent).xGetSystemCall }.ok_or(ffi::SQLITE_MISUSE)?;
    let set = unsafe { (*parent).xSetSystemCall }.ok_or(ffi::SQLITE_MISUSE)?;
    let fetch = |name: &'static [u8]| unsafe { get(parent, name.as_ptr().cast()) };
    // SAFETY: the pinned Unix parent documents these entries with exactly these C signatures.
    let (open, fstat, mmap, munmap) = unsafe {
        (
            std::mem::transmute::<unsafe extern "C" fn(), OpenFn>(
                fetch(b"open\0").ok_or(ffi::SQLITE_NOTFOUND)?,
            ),
            std::mem::transmute::<unsafe extern "C" fn(), FstatFn>(
                fetch(b"fstat\0").ok_or(ffi::SQLITE_NOTFOUND)?,
            ),
            std::mem::transmute::<unsafe extern "C" fn(), MmapFn>(
                fetch(b"mmap\0").ok_or(ffi::SQLITE_NOTFOUND)?,
            ),
            std::mem::transmute::<unsafe extern "C" fn(), MunmapFn>(
                fetch(b"munmap\0").ok_or(ffi::SQLITE_NOTFOUND)?,
            ),
        )
    };
    let fchmod = fetch(b"fchmod\0")
        .map(|call| unsafe { std::mem::transmute::<unsafe extern "C" fn(), FchmodFn>(call) });
    let fchown = fetch(b"fchown\0")
        .map(|call| unsafe { std::mem::transmute::<unsafe extern "C" fn(), FchownFn>(call) });
    let (stat, lstat, readlink, access) = unsafe {
        (
            std::mem::transmute::<unsafe extern "C" fn(), StatFn>(
                fetch(b"stat\0").ok_or(ffi::SQLITE_NOTFOUND)?,
            ),
            std::mem::transmute::<unsafe extern "C" fn(), StatFn>(
                fetch(b"lstat\0").ok_or(ffi::SQLITE_NOTFOUND)?,
            ),
            std::mem::transmute::<unsafe extern "C" fn(), ReadlinkFn>(
                fetch(b"readlink\0").ok_or(ffi::SQLITE_NOTFOUND)?,
            ),
            std::mem::transmute::<unsafe extern "C" fn(), AccessFn>(
                fetch(b"access\0").ok_or(ffi::SQLITE_NOTFOUND)?,
            ),
        )
    };
    if ORIGINALS
        .set(Originals {
            open,
            stat,
            lstat,
            readlink,
            access,
            fchmod,
            fchown,
            fstat,
            mmap,
            munmap,
        })
        .is_err()
    {
        return Err(ffi::SQLITE_MISUSE);
    }
    let install = |name: &'static [u8], call: unsafe extern "C" fn()| {
        let result = unsafe { set(parent, name.as_ptr().cast(), Some(call)) };
        if result == ffi::SQLITE_OK {
            Ok(())
        } else {
            Err(result)
        }
    };
    // SAFETY: each hook has the C signature of the entry it replaces.
    unsafe {
        install(
            b"open\0",
            std::mem::transmute::<OpenFn, unsafe extern "C" fn()>(hook_open),
        )?;
        install(
            b"stat\0",
            std::mem::transmute::<StatFn, unsafe extern "C" fn()>(hook_stat),
        )?;
        install(
            b"lstat\0",
            std::mem::transmute::<StatFn, unsafe extern "C" fn()>(hook_lstat),
        )?;
        install(
            b"readlink\0",
            std::mem::transmute::<ReadlinkFn, unsafe extern "C" fn()>(hook_readlink),
        )?;
        install(
            b"access\0",
            std::mem::transmute::<AccessFn, unsafe extern "C" fn()>(hook_access),
        )?;
        install(
            b"fstat\0",
            std::mem::transmute::<FstatFn, unsafe extern "C" fn()>(hook_fstat),
        )?;
        install(
            b"mmap\0",
            std::mem::transmute::<MmapFn, unsafe extern "C" fn()>(hook_mmap),
        )?;
        install(
            b"munmap\0",
            std::mem::transmute::<MunmapFn, unsafe extern "C" fn()>(hook_munmap),
        )?;
        if fchmod.is_some() {
            install(
                b"fchmod\0",
                std::mem::transmute::<FchmodFn, unsafe extern "C" fn()>(hook_fchmod),
            )?;
        }
        if fchown.is_some() {
            install(
                b"fchown\0",
                std::mem::transmute::<FchownFn, unsafe extern "C" fn()>(hook_fchown),
            )?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Work limit: a deterministic bound on SQLite virtual-machine work for one source read.
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct WorkLimit {
    deadline: Instant,
    ticks_left: u64,
}

/// Guard for the per-thread SQLite work limit; the connection's progress handler enforces it.
pub struct WorkGuard(());

impl WorkGuard {
    /// Limits SQLite work on this thread to `deadline` of wall time and `max_ticks` progress
    /// callbacks (`SQLITE_PROGRESS_INTERVAL` VM instructions each), whichever ends first.
    pub fn begin(deadline: Duration, max_ticks: u64) -> Self {
        WORK.with(|work| {
            work.set(Some(WorkLimit {
                deadline: Instant::now() + deadline,
                ticks_left: max_ticks,
            }));
        });
        Self(())
    }
}

impl Drop for WorkGuard {
    fn drop(&mut self) {
        WORK.with(|work| work.set(None));
    }
}

extern "C" fn progress_callback(_state: *mut c_void) -> c_int {
    WORK.with(|work| match work.get() {
        Some(mut limit) => {
            limit.ticks_left = limit.ticks_left.saturating_sub(1);
            work.set(Some(limit));
            c_int::from(limit.ticks_left == 0 || Instant::now() >= limit.deadline)
        }
        None => 0,
    })
}

#[cfg(feature = "test-faults")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VfsMetrics {
    pub opens: usize,
    pub stripped_write_capable_requests: usize,
    /// Delegated opens whose reported flags still carried a write bit.
    pub write_capable_opens: usize,
    pub writes: usize,
    pub truncates: usize,
    pub syncs: usize,
    pub deletes: usize,
    /// Delegated `xShmMap` attempts.
    pub shared_memory_maps: usize,
    /// Descriptors the kernel reported as opened for writing (`F_GETFL`), independent of flags.
    pub effective_write_capable_descriptors: usize,
    pub nonregular_descriptors_rejected: usize,
    pub descriptors_verified: usize,
    /// `fchmod`/`fchown` calls the parent attempted for a source file and this VFS blocked.
    pub metadata_effects_blocked: usize,
    pub readonly_shared_memory_maps: usize,
    /// By-name opens whose descriptor the kernel-level hook verified regular and bound.
    pub opens_verified: usize,
    /// By-name opens refused: not the expected inode, not regular, or an alias.
    pub opens_refused: usize,
    pub writable_shared_memory_maps_rejected: usize,
    pub unverified_shared_memory_maps_rejected: usize,
    /// Read-only mappings refused because they were not made from the inode the `-shm` sidecar
    /// path names (a node reused after the sidecar was replaced, or one never bound to a file).
    pub shared_memory_identity_rejected: usize,
}

#[cfg(feature = "test-faults")]
#[derive(Default)]
struct Counters {
    opens: AtomicUsize,
    stripped_write_capable_requests: AtomicUsize,
    write_capable_opens: AtomicUsize,
    writes: AtomicUsize,
    truncates: AtomicUsize,
    syncs: AtomicUsize,
    deletes: AtomicUsize,
    shared_memory_maps: AtomicUsize,
}

struct VfsContext {
    parent: NonNull<ffi::sqlite3_vfs>,
    #[cfg(feature = "test-faults")]
    counters: Counters,
}

struct RegisteredVfs {
    _context: Box<VfsContext>,
    _vfs: Box<ffi::sqlite3_vfs>,
}

// SAFETY: the registered VFS is never mutated after initialization; callback state is atomic and
// the delegated system VFS outlives this process-global owner. Moving the owner moves only
// boxes, so SQLite's registered addresses remain stable.
unsafe impl Send for RegisteredVfs {}
unsafe impl Sync for RegisteredVfs {}

#[derive(Clone, Copy, Eq, PartialEq)]
enum FileKind {
    /// Main database delegated to the pinned Unix parent (read-only, scope-checked).
    Delegated,
    /// Write-ahead log read through a descriptor this VFS opened itself; never delegated.
    Wal,
}

#[repr(C)]
struct ReadOnlyFile {
    base: ffi::sqlite3_file,
    kind: FileKind,
    inner: *mut ffi::sqlite3_file,
    wal: *mut File,
    /// Database path, kept to validate the `-shm` sidecar before the parent opens it.
    path: *mut CString,
    shm_checked: bool,
    /// The inode the `-shm` sidecar path named when it was validated (`None`: it was absent).
    shm_identity: Option<(u64, u64)>,
    /// Serve the database header as the rollback-journal format (bytes 18 and 19 read as 1), so
    /// a quiescent file can be inspected without opening, creating or mapping any sidecar.
    rollback_view: bool,
    /// Committed write-ahead-log pages served over the main file in a rollback view; null when
    /// there is none.
    overlay: *mut WalOverlay,
    context: *const VfsContext,
}

#[derive(Debug, Eq, PartialEq)]
pub enum OpenError {
    InvalidPath,
    PathNotUtf8,
    EmbeddedNul,
    VfsRegistration(c_int),
    Sqlite(c_int),
    DatabasePathMismatch,
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPath => formatter.write_str("SQLite source path is not absolute"),
            Self::PathNotUtf8 => formatter.write_str("SQLite source path is not UTF-8"),
            Self::EmbeddedNul => formatter.write_str("SQLite source path contains NUL"),
            Self::VfsRegistration(code) => write!(
                formatter,
                "read-only SQLite VFS registration failed ({code})"
            ),
            Self::Sqlite(code) => write!(formatter, "read-only SQLite operation failed ({code})"),
            Self::DatabasePathMismatch => {
                formatter.write_str("SQLite opened a different database path")
            }
        }
    }
}

impl std::error::Error for OpenError {}

pub fn open_canonical(path: &Path) -> Result<Connection, OpenError> {
    if path.to_str().is_none() {
        return Err(OpenError::PathNotUtf8);
    }
    let uri = sqlite_uri(path)?;
    let vfs = vfs_name()?;
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_URI
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let connection = Connection::open_with_flags_and_vfs(uri, flags, vfs).map_err(sqlite_error)?;
    connection
        .busy_timeout(Duration::from_millis(SQLITE_BUSY_TIMEOUT_MS))
        .map_err(sqlite_error)?;
    connection
        .pragma_update(None, "query_only", true)
        .map_err(sqlite_error)?;
    // Sorting and materialization stay in memory: the source directory never gains temp files.
    connection
        .pragma_update(None, "temp_store", "MEMORY")
        .map_err(sqlite_error)?;
    // SAFETY: the handle is valid for the connection's lifetime; the callback reads only
    // thread-local state and takes no pointer argument.
    unsafe {
        ffi::sqlite3_progress_handler(
            connection.handle(),
            SQLITE_PROGRESS_INTERVAL,
            Some(progress_callback),
            ptr::null_mut(),
        );
    }
    let opened_path: String = connection
        .query_row("PRAGMA database_list", [], |row| row.get(2))
        .map_err(sqlite_error)?;
    if Some(opened_path.as_str()) != path.to_str() {
        return Err(OpenError::DatabasePathMismatch);
    }
    Ok(connection)
}

/// Committed content of a write-ahead log: the newest committed copy of every page, found by
/// walking the log's frames with SQLite's own salt and checksum rules. A frame past the last
/// valid commit is ignored, exactly as SQLite ignores it.
pub struct WalOverlay {
    wal: File,
    page_size: usize,
    /// Database size in pages after the newest commit; 0 when no commit exists.
    pages: u32,
    /// Page number to the offset of its newest committed frame header.
    frames: HashMap<u32, u64>,
}

impl WalOverlay {
    /// Walks `wal` read-only. `InvalidData` for a header SQLite would refuse.
    pub fn committed(wal: File) -> io::Result<Self> {
        use std::os::unix::fs::FileExt;
        let bad = || io::Error::new(io::ErrorKind::InvalidData, "invalid write-ahead log");
        let mut header = [0_u8; 32];
        wal.read_exact_at(&mut header, 0).map_err(|_| bad())?;
        let word = |bytes: &[u8], at: usize| {
            u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        let magic = word(&header, 0);
        if magic != 0x377f_0682 && magic != 0x377f_0683 {
            return Err(bad());
        }
        let big_endian_words = magic & 1 == 1;
        let page_size = word(&header, 8) as usize;
        if !(512..=65_536).contains(&page_size) || !page_size.is_power_of_two() {
            return Err(bad());
        }
        // Checksum over 8-byte units, words read in the byte order the magic number selects.
        let checksum = |seed: (u32, u32), bytes: &[u8]| {
            let (mut s0, mut s1) = seed;
            for unit in bytes.as_chunks::<8>().0 {
                let read = |at: usize| {
                    let raw = [unit[at], unit[at + 1], unit[at + 2], unit[at + 3]];
                    if big_endian_words {
                        u32::from_be_bytes(raw)
                    } else {
                        u32::from_le_bytes(raw)
                    }
                };
                s0 = s0.wrapping_add(read(0)).wrapping_add(s1);
                s1 = s1.wrapping_add(read(4)).wrapping_add(s0);
            }
            (s0, s1)
        };
        let mut running = checksum((0, 0), &header[..24]);
        if running != (word(&header, 24), word(&header, 28)) {
            return Err(bad());
        }
        let salt = (word(&header, 16), word(&header, 20));
        let frame_len = 24 + page_size as u64;
        let length = wal.metadata()?.len();
        let mut committed = HashMap::new();
        let mut pending: HashMap<u32, u64> = HashMap::new();
        let mut pages = 0_u32;
        let mut buffer = vec![0_u8; page_size];
        let mut offset = 32_u64;
        while offset + frame_len <= length {
            let mut frame = [0_u8; 24];
            if wal.read_exact_at(&mut frame, offset).is_err()
                || wal.read_exact_at(&mut buffer, offset + 24).is_err()
                || (word(&frame, 8), word(&frame, 12)) != salt
            {
                break;
            }
            let next = checksum(checksum(running, &frame[..8]), &buffer);
            if next != (word(&frame, 16), word(&frame, 20)) {
                break;
            }
            running = next;
            pending.insert(word(&frame, 0), offset);
            if word(&frame, 4) != 0 {
                // A commit frame: everything up to it is part of the committed state.
                committed.extend(pending.drain());
                pages = word(&frame, 4);
            }
            offset += frame_len;
        }
        Ok(Self {
            wal,
            page_size,
            pages,
            frames: committed,
        })
    }

    /// The `user_version` committed in the log, if the log rewrites page one.
    pub fn user_version(&self) -> io::Result<Option<u32>> {
        use std::os::unix::fs::FileExt;
        let Some(offset) = self.frames.get(&1) else {
            return Ok(None);
        };
        let mut word = [0_u8; 4];
        self.wal.read_exact_at(&mut word, offset + 24 + 60)?;
        Ok(Some(u32::from_be_bytes(word)))
    }
}

thread_local! {
    /// Database paths currently opened as rollback views on this thread. SQLite is told their
    /// `-wal` and `-journal` sidecars do not exist, so it never opens WAL mode or recovers.
    static VIEW_PATHS: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

/// Whether `name` is a log or journal sidecar of a database open as a rollback view.
fn hidden_sidecar(name: &[u8]) -> bool {
    VIEW_PATHS.with(|paths| {
        paths.borrow().iter().any(|path| {
            name.strip_prefix(path.as_slice())
                .is_some_and(|rest| rest == b"-wal" || rest == b"-journal")
        })
    })
}

/// Runs `inspect` on a read-only view of a quiescent database file whose WAL format flag is
/// masked and whose `-wal`/`-journal` sidecars are hidden from SQLite, so no sidecar is opened,
/// created, mapped or recovered. With no overlay the caller must have proved that no non-empty
/// WAL exists; with one, the committed pages of that log are served over the main file, so a
/// store whose newest schema lives only in its log is seen as SQLite would see it after
/// recovery, without recovering and without touching any file.
pub fn with_rollback_view<T>(
    path: &Path,
    overlay: Option<WalOverlay>,
    inspect: impl FnOnce(&Connection) -> T,
) -> Result<T, OpenError> {
    if path.to_str().is_none() {
        return Err(OpenError::PathNotUtf8);
    }
    let uri = encode_path_uri(path, "mode=ro&quotern_rollback_view=1")?;
    let vfs = vfs_name()?;
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_URI
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    VIEW_PATHS.with(|paths| {
        paths
            .borrow_mut()
            .push(path.as_os_str().as_bytes().to_vec())
    });
    PENDING_OVERLAY.with(|slot| *slot.borrow_mut() = overlay.map(Box::new));
    let opened = Connection::open_with_flags_and_vfs(uri, flags, vfs).map_err(sqlite_error);
    // An overlay the open did not consume (open failed before the main file) is dropped here.
    PENDING_OVERLAY.with(|slot| slot.borrow_mut().take());
    let result = opened.and_then(|connection| {
        connection
            .pragma_update(None, "query_only", true)
            .map_err(sqlite_error)?;
        connection
            .pragma_update(None, "temp_store", "MEMORY")
            .map_err(sqlite_error)?;
        Ok(inspect(&connection))
    });
    VIEW_PATHS.with(|paths| {
        paths.borrow_mut().pop();
    });
    result
}

/// Change witness of a database snapshot, independent of SQLite's own cursors: the main file's
/// size and change counter plus the write-ahead log's size and header (salts and checkpoint
/// sequence). Any commit appends to the log or restarts it under new salts, and any checkpoint
/// moves the change counter, so two equal witnesses bracket a period with no commit. Each file
/// is opened non-blocking and charged against the VFS meter before its `fstat`.
pub fn snapshot_witness(path: &Path) -> io::Result<u64> {
    use std::os::unix::fs::FileExt;
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    let mut mix = |bytes: &[u8]| {
        for byte in bytes {
            hash = (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    let (main, metadata) = open_regular_with(path, &mut charge_io)?;
    let mut header = [0_u8; 100];
    let read = main.read_at(&mut header, 0)?;
    mix(&metadata.len().to_le_bytes());
    mix(&header[..read.min(40)]);
    match open_regular_with(&sidecar_path(path, "-wal"), &mut charge_io) {
        Ok((wal, metadata)) => {
            let mut head = [0_u8; 32];
            let read = wal.read_at(&mut head, 0)?;
            mix(&[1]);
            mix(&metadata.len().to_le_bytes());
            mix(&head[..read]);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => mix(&[0]),
        Err(error) => return Err(error),
    }
    Ok(hash)
}

// ---------------------------------------------------------------------------------------------
// Directory-relative opens: a path is never re-resolved between validation and use.
// ---------------------------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod create_flags {
    pub const CREAT: i32 = 0x0200;
    pub const EXCL: i32 = 0x0800;
    pub const TRUNC: i32 = 0x0400;
    pub const CLOEXEC: i32 = 0x0100_0000;
}

#[cfg(target_os = "linux")]
mod create_flags {
    pub const CREAT: i32 = 0o100;
    pub const EXCL: i32 = 0o200;
    pub const TRUNC: i32 = 0o1000;
    pub const CLOEXEC: i32 = 0o200_0000;
}

unsafe extern "C" {
    fn openat(directory: c_int, path: *const c_char, flags: c_int, ...) -> c_int;
    fn mkdirat(directory: c_int, path: *const c_char, mode: c_uint) -> c_int;
}

fn component_cstring(name: &std::ffi::OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path component contains NUL"))
}

/// Opens an existing directory without following a final symlink.
pub fn open_directory(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let handle = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(
            crate::ingest::fs::open_flags::NOFOLLOW
                | crate::ingest::fs::open_flags::NONBLOCK
                | crate::ingest::fs::open_flags::DIRECTORY,
        )
        .open(path)?;
    if !handle.metadata()?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path is not a directory",
        ));
    }
    Ok(handle)
}

/// Opens the named child directory of `parent`, creating it first when absent, relative to the
/// held handle and without following a symlink.
pub fn open_or_create_directory_at(parent: &File, name: &std::ffi::OsStr) -> io::Result<File> {
    use std::os::fd::AsRawFd;
    let name = component_cstring(name)?;
    // SAFETY: `parent` is a live descriptor and `name` is a NUL-terminated single component.
    let made = unsafe { mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o777) };
    if made != 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists {
            return Err(error);
        }
    }
    let flags = crate::ingest::fs::open_flags::NOFOLLOW
        | crate::ingest::fs::open_flags::DIRECTORY
        | create_flags::CLOEXEC;
    // SAFETY: as above; the flags select a read-only directory open that never follows links.
    let fd = unsafe { openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by `openat` and is owned by nothing else.
    let handle = unsafe { File::from_raw_fd(fd) };
    if !handle.metadata()?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path is not a directory",
        ));
    }
    Ok(handle)
}

/// Opens the named regular file of `parent` read-write without following a symlink, creating it
/// (owner-only) when absent. Returns the descriptor and whether it was created.
pub fn open_or_create_file_at(parent: &File, name: &std::ffi::OsStr) -> io::Result<(File, bool)> {
    use std::os::fd::AsRawFd;
    let name = component_cstring(name)?;
    let base = crate::ingest::fs::open_flags::NOFOLLOW
        | crate::ingest::fs::open_flags::NONBLOCK
        | create_flags::CLOEXEC;
    for (flags, created) in [
        (base, false),
        (base | create_flags::CREAT | create_flags::EXCL, true),
    ] {
        // SAFETY: `parent` is a live descriptor; `name` is NUL-terminated; the mode is only read
        // when the creating flags are present.
        let fd = unsafe {
            openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                flags | 2,
                0o600 as c_uint,
            )
        };
        if fd >= 0 {
            // SAFETY: `fd` was just returned by `openat` and is owned by nothing else.
            return Ok((unsafe { File::from_raw_fd(fd) }, created));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::NotFound {
            return Err(error);
        }
    }
    Err(io::Error::from(io::ErrorKind::NotFound))
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FileIdentity {
    pub exists: bool,
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DatabaseIdentity {
    pub database: FileIdentity,
    pub wal: FileIdentity,
    pub shm: FileIdentity,
    pub journal: FileIdentity,
}

impl DatabaseIdentity {
    /// Stable text form persisted beside cursors so a resumed sweep can prove it is the same
    /// database and sidecar set.
    pub fn key(&self) -> String {
        let part = |identity: &FileIdentity| {
            if identity.exists {
                format!("{}:{}", identity.device, identity.inode)
            } else {
                "-".to_owned()
            }
        };
        format!(
            "{}|{}|{}|{}",
            part(&self.database),
            part(&self.wal),
            part(&self.shm),
            part(&self.journal)
        )
    }
}

pub fn preflight<F: SourceFs>(
    fs: &F,
    path: &Path,
    counters: &mut PassCounters,
) -> Result<DatabaseIdentity, FailureCode> {
    if !path.is_absolute() || path.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES {
        return Err(FailureCode::RootInvalid);
    }
    let database_metadata = counted_metadata(fs, path, counters)?.ok_or(FailureCode::NotSqlite)?;
    if !database_metadata.is_file() {
        return Err(FailureCode::NotSqlite);
    }
    if counters.header_reads >= MAX_HEADER_READS {
        return Err(FailureCode::LimitExceeded);
    }
    counters.header_reads += 1;
    counters.source_opens = counters.source_opens.saturating_add(1);
    let header = fs.read_header(path, counters).map_err(header_failure)?;
    if header.len() != 100 || !header.starts_with(b"SQLite format 3\0") {
        return Err(FailureCode::NotSqlite);
    }
    let database = file_identity(&database_metadata);
    let wal = counted_identity(fs, &sidecar_path(path, "-wal"), counters)?;
    let shm = counted_identity(fs, &sidecar_path(path, "-shm"), counters)?;
    let journal = counted_identity(fs, &sidecar_path(path, "-journal"), counters)?;
    if journal.exists {
        return Err(FailureCode::HotJournal);
    }
    if header[18] == 2 && header[19] == 2 && (!wal.exists || !shm.exists) {
        return Err(FailureCode::SourceIdle);
    }
    Ok(DatabaseIdentity {
        database,
        wal,
        shm,
        journal,
    })
}

fn header_failure(error: io::Error) -> FailureCode {
    if budget_exhausted(&error) {
        return FailureCode::LimitExceeded;
    }
    match error.kind() {
        io::ErrorKind::NotFound => FailureCode::SourceChanging,
        io::ErrorKind::InvalidInput => FailureCode::RootOverlap,
        _ => FailureCode::Io,
    }
}

/// The database and sidecar identity set as it is right now, with the main file's stamp.
pub fn current_state<F: SourceFs>(
    fs: &F,
    path: &Path,
    counters: &mut PassCounters,
) -> Result<(DatabaseIdentity, Option<crate::ingest::fs::FileStamp>), FailureCode> {
    let database = counted_metadata(fs, path, counters)?;
    let identity = DatabaseIdentity {
        database: database.as_ref().map(file_identity).unwrap_or_default(),
        wal: counted_identity(fs, &sidecar_path(path, "-wal"), counters)?,
        shm: counted_identity(fs, &sidecar_path(path, "-shm"), counters)?,
        journal: counted_identity(fs, &sidecar_path(path, "-journal"), counters)?,
    };
    Ok((
        identity,
        database.as_ref().map(crate::ingest::fs::FileStamp::of),
    ))
}

pub fn identity_unchanged<F: SourceFs>(
    fs: &F,
    path: &Path,
    before: DatabaseIdentity,
    counters: &mut PassCounters,
) -> Result<bool, FailureCode> {
    let after = DatabaseIdentity {
        database: counted_identity(fs, path, counters)?,
        wal: counted_identity(fs, &sidecar_path(path, "-wal"), counters)?,
        shm: counted_identity(fs, &sidecar_path(path, "-shm"), counters)?,
        journal: counted_identity(fs, &sidecar_path(path, "-journal"), counters)?,
    };
    Ok(before == after)
}

/// One metadata call, charged against the shared per-pass ceiling by the filesystem itself.
fn counted_metadata<F: SourceFs>(
    fs: &F,
    path: &Path,
    counters: &mut PassCounters,
) -> Result<Option<Metadata>, FailureCode> {
    match fs.metadata(path, counters) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(FailureCode::SourceChanging),
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if budget_exhausted(&error) => Err(FailureCode::LimitExceeded),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(FailureCode::Io),
    }
}

/// Sidecars must be regular files: a FIFO, socket or device would block or misdirect SQLite.
fn counted_identity<F: SourceFs>(
    fs: &F,
    path: &Path,
    counters: &mut PassCounters,
) -> Result<FileIdentity, FailureCode> {
    match counted_metadata(fs, path, counters)? {
        Some(metadata) if !metadata.is_file() => Err(FailureCode::Io),
        Some(metadata) => Ok(file_identity(&metadata)),
        None => Ok(FileIdentity::default()),
    }
}

fn file_identity(metadata: &Metadata) -> FileIdentity {
    FileIdentity {
        exists: true,
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name = OsString::from(path.as_os_str());
    name.push(suffix);
    PathBuf::from(name)
}

pub fn sqlite_uri(path: &Path) -> Result<String, OpenError> {
    encode_path_uri(path, "mode=ro&readonly_shm=1")
}

/// Percent-encodes an absolute NUL-free path into a SQLite `file:` URI with the given query.
pub fn encode_path_uri(path: &Path, query: &str) -> Result<String, OpenError> {
    if !path.is_absolute() {
        return Err(OpenError::InvalidPath);
    }
    let bytes = path.as_os_str().as_bytes();
    if bytes.contains(&0) {
        return Err(OpenError::EmbeddedNul);
    }
    let mut uri = String::with_capacity(bytes.len() + 40);
    uri.push_str("file:");
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || b"-._~/".contains(byte) {
            uri.push(*byte as char);
        } else {
            use std::fmt::Write as _;
            write!(uri, "%{byte:02X}").map_err(|_| OpenError::InvalidPath)?;
        }
    }
    uri.push('?');
    uri.push_str(query);
    Ok(uri)
}

pub fn linked_sqlite_identity(connection: &Connection) -> rusqlite::Result<(String, String)> {
    connection.query_row("SELECT sqlite_version(), sqlite_source_id()", [], |row| {
        Ok((row.get(0)?, row.get(1)?))
    })
}

#[cfg(feature = "test-faults")]
pub fn vfs_metrics() -> Result<VfsMetrics, OpenError> {
    let context = vfs_context()?;
    use Ordering::Relaxed;
    Ok(VfsMetrics {
        opens: context.counters.opens.load(Relaxed),
        stripped_write_capable_requests: context
            .counters
            .stripped_write_capable_requests
            .load(Relaxed),
        write_capable_opens: context.counters.write_capable_opens.load(Relaxed),
        writes: context.counters.writes.load(Relaxed),
        truncates: context.counters.truncates.load(Relaxed),
        syncs: context.counters.syncs.load(Relaxed),
        deletes: context.counters.deletes.load(Relaxed),
        shared_memory_maps: context.counters.shared_memory_maps.load(Relaxed),
        effective_write_capable_descriptors: HOOK_STATS.writable_descriptors.load(Relaxed),
        nonregular_descriptors_rejected: HOOK_STATS.nonregular_descriptors.load(Relaxed),
        descriptors_verified: HOOK_STATS.descriptors_verified.load(Relaxed),
        metadata_effects_blocked: HOOK_STATS.metadata_effects_blocked.load(Relaxed),
        readonly_shared_memory_maps: HOOK_STATS.readonly_maps.load(Relaxed),
        opens_verified: HOOK_STATS.opens_verified.load(Relaxed),
        opens_refused: HOOK_STATS.opens_refused.load(Relaxed),
        writable_shared_memory_maps_rejected: HOOK_STATS.writable_maps_rejected.load(Relaxed),
        unverified_shared_memory_maps_rejected: HOOK_STATS.unverified_maps_rejected.load(Relaxed),
        shared_memory_identity_rejected: HOOK_STATS.identity_rejected.load(Relaxed),
    })
}

#[cfg(feature = "test-faults")]
pub fn reset_vfs_metrics() -> Result<(), OpenError> {
    let context = vfs_context()?;
    use Ordering::Relaxed;
    context.counters.opens.store(0, Relaxed);
    context
        .counters
        .stripped_write_capable_requests
        .store(0, Relaxed);
    context.counters.write_capable_opens.store(0, Relaxed);
    context.counters.writes.store(0, Relaxed);
    context.counters.truncates.store(0, Relaxed);
    context.counters.syncs.store(0, Relaxed);
    context.counters.deletes.store(0, Relaxed);
    context.counters.shared_memory_maps.store(0, Relaxed);
    for stat in [
        &HOOK_STATS.writable_descriptors,
        &HOOK_STATS.nonregular_descriptors,
        &HOOK_STATS.descriptors_verified,
        &HOOK_STATS.metadata_effects_blocked,
        &HOOK_STATS.readonly_maps,
        &HOOK_STATS.writable_maps_rejected,
        &HOOK_STATS.unverified_maps_rejected,
        &HOOK_STATS.identity_rejected,
        &HOOK_STATS.opens_verified,
        &HOOK_STATS.opens_refused,
    ] {
        stat.store(0, Relaxed);
    }
    Ok(())
}

fn sqlite_error(error: rusqlite::Error) -> OpenError {
    match error {
        rusqlite::Error::SqliteFailure(code, _) => OpenError::Sqlite(code.extended_code),
        _ => OpenError::Sqlite(ffi::SQLITE_ERROR),
    }
}

fn vfs_name() -> Result<&'static CStr, OpenError> {
    match &*REGISTERED_VFS {
        Ok(_) => Ok(CStr::from_bytes_with_nul(VFS_NAME).expect("static VFS name is terminated")),
        Err(code) => Err(OpenError::VfsRegistration(*code)),
    }
}

#[cfg(feature = "test-faults")]
fn vfs_context() -> Result<&'static VfsContext, OpenError> {
    match &*REGISTERED_VFS {
        Ok(registered) => Ok(&registered._context),
        Err(code) => Err(OpenError::VfsRegistration(*code)),
    }
}

fn register_vfs() -> Result<RegisteredVfs, c_int> {
    // The parent is pinned by name: only SQLite's POSIX "unix" VFS has the syscall table and
    // inode-shared shared-memory behavior this wrapper depends on. Any other default is refused.
    // SAFETY: the name is NUL-terminated; SQLite returns a stable registered VFS or NULL.
    let parent = NonNull::new(unsafe { ffi::sqlite3_vfs_find(c"unix".as_ptr()) })
        .ok_or(ffi::SQLITE_NOTFOUND)?;
    let (parent_size, parent_version, parent_name) = unsafe {
        let vfs = parent.as_ptr();
        (
            (*vfs).szOsFile,
            (*vfs).iVersion,
            CStr::from_ptr((*vfs).zName),
        )
    };
    if parent_name.to_bytes() != b"unix" || parent_version < 3 || parent_size <= 0 {
        return Err(ffi::SQLITE_MISUSE);
    }
    let size = size_of::<ReadOnlyFile>()
        .checked_add(parent_size as usize)
        .and_then(|size| c_int::try_from(size).ok())
        .ok_or(ffi::SQLITE_MISUSE)?;
    unsafe { install_hooks(parent)? };
    let mut context = Box::new(VfsContext {
        parent,
        #[cfg(feature = "test-faults")]
        counters: Counters::default(),
    });
    // SAFETY: copied callbacks delegate to the stable parent VFS; the owning boxes below
    // keep both the wrapper and its context at fixed addresses after registration.
    let mut vfs = Box::new(unsafe { ptr::read(parent.as_ptr()) });
    vfs.pNext = ptr::null_mut();
    vfs.szOsFile = size;
    vfs.zName = VFS_NAME.as_ptr().cast();
    vfs.pAppData = (&mut *context as *mut VfsContext).cast();
    vfs.xOpen = Some(vfs_open);
    vfs.xDelete = Some(vfs_delete);
    vfs.xAccess = Some(vfs_access);
    vfs.xFullPathname = Some(vfs_full_pathname);
    vfs.xDlOpen = Some(vfs_dl_open);
    vfs.xDlError = Some(vfs_dl_error);
    vfs.xDlSym = Some(vfs_dl_sym);
    vfs.xDlClose = Some(vfs_dl_close);
    vfs.xRandomness = Some(vfs_randomness);
    vfs.xSleep = Some(vfs_sleep);
    vfs.xCurrentTime = Some(vfs_current_time);
    vfs.xGetLastError = Some(vfs_get_last_error);
    vfs.xCurrentTimeInt64 = Some(vfs_current_time_int64);
    vfs.xSetSystemCall = Some(vfs_set_system_call);
    vfs.xGetSystemCall = Some(vfs_get_system_call);
    vfs.xNextSystemCall = Some(vfs_next_system_call);
    let result = unsafe { ffi::sqlite3_vfs_register(&mut *vfs, 0) };
    if result != ffi::SQLITE_OK {
        return Err(result);
    }
    Ok(RegisteredVfs {
        _context: context,
        _vfs: vfs,
    })
}

unsafe fn context(vfs: *mut ffi::sqlite3_vfs) -> &'static VfsContext {
    // SAFETY: callbacks are invoked only for our registered VFS; its context is leaked.
    unsafe { &*((*vfs).pAppData.cast::<VfsContext>()) }
}

#[cfg(feature = "test-faults")]
fn count(context: &VfsContext, select: fn(&Counters) -> &AtomicUsize) {
    select(&context.counters).fetch_add(1, Ordering::Relaxed);
}

unsafe extern "C" fn vfs_open(
    vfs: *mut ffi::sqlite3_vfs,
    name: ffi::sqlite3_filename,
    file: *mut ffi::sqlite3_file,
    requested_flags: c_int,
    out_flags: *mut c_int,
) -> c_int {
    let context = unsafe { context(vfs) };
    #[cfg(feature = "test-faults")]
    {
        count(context, |counters| &counters.opens);
        if requested_flags & WRITE_FLAGS != 0 {
            count(context, |counters| {
                &counters.stripped_write_capable_requests
            });
        }
    }
    if name.is_null() || file.is_null() {
        return ffi::SQLITE_READONLY;
    }
    let file_type = requested_flags & FILE_TYPE_MASK;
    let flags = (requested_flags & !WRITE_FLAGS) | ffi::SQLITE_OPEN_READONLY;
    // SAFETY: SQLite passes a NUL-terminated database or sidecar path.
    let path = PathBuf::from(std::ffi::OsStr::from_bytes(
        unsafe { CStr::from_ptr(name) }.to_bytes(),
    ));
    let wrapper = file.cast::<ReadOnlyFile>();
    match file_type {
        ffi::SQLITE_OPEN_WAL => unsafe { open_wal(context, &path, wrapper, flags, out_flags) },
        ffi::SQLITE_OPEN_MAIN_DB => unsafe {
            open_main(context, &path, name, wrapper, flags, out_flags)
        },
        // Journals, sub-journals, super-journals and temporary files would all need writes.
        _ => ffi::SQLITE_CANTOPEN,
    }
}

unsafe fn open_wal(
    context: &'static VfsContext,
    path: &Path,
    wrapper: *mut ReadOnlyFile,
    flags: c_int,
    out_flags: *mut c_int,
) -> c_int {
    // The write-ahead log is read through a descriptor opened here, read-only, without
    // following links and without blocking, so no delegated `open` can create, chmod or block.
    // Its `fstat` is charged to the source read before it runs.
    let Ok((wal, _)) = open_regular_with(path, &mut charge_io) else {
        return ffi::SQLITE_CANTOPEN;
    };
    // SAFETY: SQLite allocated `szOsFile` bytes, which cover the wrapper.
    unsafe {
        ptr::write(
            wrapper,
            ReadOnlyFile {
                base: ffi::sqlite3_file {
                    pMethods: &READ_ONLY_IO,
                },
                kind: FileKind::Wal,
                inner: ptr::null_mut(),
                wal: Box::into_raw(Box::new(wal)),
                path: ptr::null_mut(),
                shm_checked: true,
                shm_identity: None,
                rollback_view: false,
                overlay: ptr::null_mut(),
                context,
            },
        );
        if !out_flags.is_null() {
            *out_flags = flags;
        }
    }
    ffi::SQLITE_OK
}

unsafe fn open_main(
    context: &'static VfsContext,
    path: &Path,
    name: ffi::sqlite3_filename,
    wrapper: *mut ReadOnlyFile,
    flags: c_int,
    out_flags: *mut c_int,
) -> c_int {
    // Pre-open probe: a regular file, reached without blocking, whose identity the parent's
    // by-name open must reproduce. The probe's `fstat` is charged before it runs.
    let Ok((probe, probed)) = open_regular_with(path, &mut charge_io) else {
        return ffi::SQLITE_CANTOPEN;
    };
    drop(probe);
    let Ok(db_path) = CString::new(path.as_os_str().as_bytes()) else {
        return ffi::SQLITE_CANTOPEN;
    };
    let parent = context.parent.as_ptr();
    let Some(open) = (unsafe { (*parent).xOpen }) else {
        return ffi::SQLITE_CANTOPEN;
    };
    let inner = unsafe {
        wrapper
            .cast::<u8>()
            .add(size_of::<ReadOnlyFile>())
            .cast::<ffi::sqlite3_file>()
    };
    let inner_size = unsafe { (*parent).szOsFile as usize };
    let rollback_view =
        unsafe { ffi::sqlite3_uri_boolean(name, c"quotern_rollback_view".as_ptr(), 0) } != 0;
    let overlay = if rollback_view {
        PENDING_OVERLAY.with(|slot| slot.borrow_mut().take())
    } else {
        None
    };
    // SAFETY: the VFS reserves the wrapper followed by a parent-sized, pointer-aligned region
    // for the delegated Unix sqlite3_file.
    unsafe {
        ptr::write_bytes(inner.cast::<u8>(), 0, inner_size);
        ptr::write(
            wrapper,
            ReadOnlyFile {
                base: ffi::sqlite3_file {
                    pMethods: ptr::null(),
                },
                kind: FileKind::Delegated,
                inner,
                wal: ptr::null_mut(),
                path: Box::into_raw(Box::new(db_path)),
                shm_checked: false,
                shm_identity: None,
                rollback_view,
                overlay: overlay.map_or(ptr::null_mut(), Box::into_raw),
                context,
            },
        );
    }
    let release = || unsafe {
        drop(Box::from_raw((*wrapper).path));
        if !(*wrapper).overlay.is_null() {
            drop(Box::from_raw((*wrapper).overlay));
        }
    };
    // The parent opens the database by name. The kernel-level `open` hook checks the descriptor
    // it obtains against the probed inode, so a path swapped for the instant of the open (a
    // FIFO, or another database restored before any later path check) is refused, not read.
    let bound = ExpectGuard::register(
        path.as_os_str().as_bytes().to_vec(),
        Some((probed.dev(), probed.ino())),
    );
    let mut opened_flags = 0;
    let result = {
        let _scope = Scope::enter();
        unsafe { open(parent, name, inner, flags, &mut opened_flags) }
    };
    let fail = |code: c_int| {
        if let Some(close) = unsafe { (*inner).pMethods.as_ref().and_then(|m| m.xClose) } {
            let _scope = Scope::enter();
            unsafe { close(inner) };
        }
        release();
        code
    };
    if result != ffi::SQLITE_OK {
        release();
        return result;
    }
    if !bound.matched() {
        return fail(ffi::SQLITE_CANTOPEN);
    }
    if opened_flags & ffi::SQLITE_OPEN_READONLY == 0 || opened_flags & WRITE_FLAGS != 0 {
        #[cfg(feature = "test-faults")]
        count(context, |counters| &counters.write_capable_opens);
        return fail(ffi::SQLITE_READONLY);
    }
    unsafe {
        (*wrapper).base.pMethods = &READ_ONLY_IO;
        if !out_flags.is_null() {
            *out_flags = opened_flags;
        }
    }
    ffi::SQLITE_OK
}

unsafe extern "C" fn vfs_delete(
    vfs: *mut ffi::sqlite3_vfs,
    _name: *const c_char,
    _sync_dir: c_int,
) -> c_int {
    #[cfg(feature = "test-faults")]
    count(unsafe { context(vfs) }, |counters| &counters.deletes);
    let _ = vfs;
    ffi::SQLITE_READONLY
}

unsafe extern "C" fn vfs_access(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    flags: c_int,
    result: *mut c_int,
) -> c_int {
    if !name.is_null()
        && !result.is_null()
        && hidden_sidecar(unsafe { CStr::from_ptr(name) }.to_bytes())
    {
        // A rollback view never sees a log or journal: it serves committed pages itself.
        unsafe { *result = 0 };
        return ffi::SQLITE_OK;
    }
    let parent = unsafe { context(vfs).parent.as_ptr() };
    let _scope = Scope::enter();
    match unsafe { (*parent).xAccess } {
        Some(access) => unsafe { access(parent, name, flags, result) },
        None => {
            if !result.is_null() {
                unsafe { *result = 0 };
            }
            ffi::SQLITE_OK
        }
    }
}

unsafe extern "C" fn vfs_full_pathname(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    size: c_int,
    output: *mut c_char,
) -> c_int {
    let parent = unsafe { context(vfs).parent.as_ptr() };
    let _scope = Scope::enter();
    match unsafe { (*parent).xFullPathname } {
        Some(full_pathname) => unsafe { full_pathname(parent, name, size, output) },
        None => ffi::SQLITE_CANTOPEN,
    }
}

unsafe extern "C" fn vfs_dl_open(vfs: *mut ffi::sqlite3_vfs, name: *const c_char) -> *mut c_void {
    let parent = unsafe { context(vfs).parent.as_ptr() };
    unsafe {
        (*parent)
            .xDlOpen
            .map_or(ptr::null_mut(), |open| open(parent, name))
    }
}

unsafe extern "C" fn vfs_dl_error(vfs: *mut ffi::sqlite3_vfs, size: c_int, output: *mut c_char) {
    let parent = unsafe { context(vfs).parent.as_ptr() };
    if let Some(error) = unsafe { (*parent).xDlError } {
        unsafe { error(parent, size, output) };
    } else if size > 0 && !output.is_null() {
        unsafe { *output = 0 };
    }
}

unsafe extern "C" fn vfs_dl_sym(
    vfs: *mut ffi::sqlite3_vfs,
    handle: *mut c_void,
    symbol: *const c_char,
) -> Option<unsafe extern "C" fn(*mut ffi::sqlite3_vfs, *mut c_void, *const c_char)> {
    let parent = unsafe { context(vfs).parent.as_ptr() };
    match unsafe { (*parent).xDlSym } {
        Some(lookup) => unsafe { lookup(parent, handle, symbol) },
        None => None,
    }
}

unsafe extern "C" fn vfs_dl_close(vfs: *mut ffi::sqlite3_vfs, handle: *mut c_void) {
    let parent = unsafe { context(vfs).parent.as_ptr() };
    if let Some(close) = unsafe { (*parent).xDlClose } {
        unsafe { close(parent, handle) };
    }
}

unsafe extern "C" fn vfs_randomness(
    vfs: *mut ffi::sqlite3_vfs,
    size: c_int,
    output: *mut c_char,
) -> c_int {
    let parent = unsafe { context(vfs).parent.as_ptr() };
    unsafe {
        (*parent)
            .xRandomness
            .map_or(0, |random| random(parent, size, output))
    }
}

unsafe extern "C" fn vfs_sleep(vfs: *mut ffi::sqlite3_vfs, microseconds: c_int) -> c_int {
    let parent = unsafe { context(vfs).parent.as_ptr() };
    unsafe {
        (*parent)
            .xSleep
            .map_or(0, |sleep| sleep(parent, microseconds))
    }
}

unsafe extern "C" fn vfs_current_time(vfs: *mut ffi::sqlite3_vfs, time: *mut f64) -> c_int {
    let parent = unsafe { context(vfs).parent.as_ptr() };
    unsafe {
        (*parent)
            .xCurrentTime
            .map_or(ffi::SQLITE_ERROR, |now| now(parent, time))
    }
}

unsafe extern "C" fn vfs_get_last_error(
    vfs: *mut ffi::sqlite3_vfs,
    size: c_int,
    output: *mut c_char,
) -> c_int {
    let parent = unsafe { context(vfs).parent.as_ptr() };
    unsafe {
        (*parent)
            .xGetLastError
            .map_or(0, |last_error| last_error(parent, size, output))
    }
}

unsafe extern "C" fn vfs_current_time_int64(
    vfs: *mut ffi::sqlite3_vfs,
    time: *mut ffi::sqlite3_int64,
) -> c_int {
    let parent = unsafe { context(vfs).parent.as_ptr() };
    match unsafe { (*parent).xCurrentTimeInt64 } {
        Some(now) => unsafe { now(parent, time) },
        None => {
            let mut julian = 0.0;
            let result = unsafe { vfs_current_time(vfs, &mut julian) };
            if result == ffi::SQLITE_OK && !time.is_null() {
                unsafe { *time = (julian * 86_400_000.0) as ffi::sqlite3_int64 };
            }
            result
        }
    }
}

extern "C" fn vfs_set_system_call(
    _vfs: *mut ffi::sqlite3_vfs,
    _name: *const c_char,
    _call: ffi::sqlite3_syscall_ptr,
) -> c_int {
    // The interposed syscall table is owned by this module; connections cannot replace it.
    ffi::SQLITE_READONLY
}

unsafe extern "C" fn vfs_get_system_call(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
) -> ffi::sqlite3_syscall_ptr {
    let parent = unsafe { context(vfs).parent.as_ptr() };
    unsafe { (*parent).xGetSystemCall.and_then(|get| get(parent, name)) }
}

unsafe extern "C" fn vfs_next_system_call(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
) -> *const c_char {
    let parent = unsafe { context(vfs).parent.as_ptr() };
    unsafe {
        (*parent)
            .xNextSystemCall
            .map_or(ptr::null(), |next| next(parent, name))
    }
}

unsafe fn wrapper<'a>(file: *mut ffi::sqlite3_file) -> &'a mut ReadOnlyFile {
    unsafe { &mut *file.cast::<ReadOnlyFile>() }
}

/// Runs a call on the delegated Unix file inside a source scope.
unsafe fn delegated<R>(
    file: *mut ffi::sqlite3_file,
    call: impl FnOnce(*mut ffi::sqlite3_file, &ffi::sqlite3_io_methods) -> R,
    absent: R,
) -> R {
    let inner = unsafe { wrapper(file) }.inner;
    match unsafe { (*inner).pMethods.as_ref() } {
        Some(methods) => {
            let _scope = Scope::enter();
            call(inner, methods)
        }
        None => absent,
    }
}

unsafe extern "C" fn file_close(file: *mut ffi::sqlite3_file) -> c_int {
    let kind = unsafe { wrapper(file) }.kind;
    let result = match kind {
        FileKind::Wal => {
            unsafe { drop(Box::from_raw(wrapper(file).wal)) };
            ffi::SQLITE_OK
        }
        FileKind::Delegated => {
            let result = unsafe {
                delegated(
                    file,
                    |inner, methods| {
                        methods
                            .xClose
                            .map_or(ffi::SQLITE_IOERR, |close| close(inner))
                    },
                    ffi::SQLITE_OK,
                )
            };
            unsafe {
                drop(Box::from_raw(wrapper(file).path));
                let overlay = wrapper(file).overlay;
                if !overlay.is_null() {
                    drop(Box::from_raw(overlay));
                }
            }
            result
        }
    };
    unsafe { wrapper(file).base.pMethods = ptr::null() };
    result
}

/// Reads a range of a rollback view: pages the log committed come from the log, every other page
/// from the main file, so the view equals the database as SQLite would see it after recovery.
unsafe fn overlay_read(
    file: *mut ffi::sqlite3_file,
    overlay: &WalOverlay,
    buffer: *mut c_void,
    amount: c_int,
    offset: ffi::sqlite3_int64,
) -> c_int {
    let (Ok(total), Ok(start)) = (usize::try_from(amount), u64::try_from(offset)) else {
        return IOERR_READ;
    };
    let page = overlay.page_size as u64;
    let mut done = 0_usize;
    let mut short = false;
    while done < total {
        let position = start + done as u64;
        let within = position % page;
        let take = (total - done).min((page - within) as usize);
        // SAFETY: `done + take <= total`, inside the buffer SQLite supplied.
        let target = unsafe { buffer.cast::<u8>().add(done) };
        let number = u32::try_from(position / page + 1).unwrap_or(u32::MAX);
        if let Some(frame) = overlay.frames.get(&number) {
            // SAFETY: as above, `take` writable bytes at `target`.
            let output = unsafe { std::slice::from_raw_parts_mut(target, take) };
            if overlay
                .wal
                .read_exact_at(output, frame + 24 + within)
                .is_err()
            {
                return IOERR_READ;
            }
        } else {
            let code = unsafe {
                delegated(
                    file,
                    |inner, methods| {
                        methods.xRead.map_or(ffi::SQLITE_IOERR, |read| {
                            read(inner, target.cast(), take as c_int, position as i64)
                        })
                    },
                    ffi::SQLITE_IOERR,
                )
            };
            match code {
                ffi::SQLITE_OK => {}
                IOERR_SHORT_READ => short = true,
                other => return other,
            }
        }
        done += take;
    }
    if short {
        IOERR_SHORT_READ
    } else {
        ffi::SQLITE_OK
    }
}

unsafe extern "C" fn file_read(
    file: *mut ffi::sqlite3_file,
    buffer: *mut c_void,
    amount: c_int,
    offset: ffi::sqlite3_int64,
) -> c_int {
    let wrapper = unsafe { wrapper(file) };
    if wrapper.kind == FileKind::Wal {
        let (Ok(length), Ok(position)) = (usize::try_from(amount), u64::try_from(offset)) else {
            return IOERR_READ;
        };
        // SAFETY: SQLite supplies a writable buffer of `amount` bytes.
        let output = unsafe { std::slice::from_raw_parts_mut(buffer.cast::<u8>(), length) };
        let wal = unsafe { &*wrapper.wal };
        let mut filled = 0;
        while filled < length {
            match wal.read_at(&mut output[filled..], position + filled as u64) {
                Ok(0) => break,
                Ok(read) => filled += read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return IOERR_READ,
            }
        }
        if filled < length {
            output[filled..].fill(0);
            return IOERR_SHORT_READ;
        }
        return ffi::SQLITE_OK;
    }
    let result = if wrapper.overlay.is_null() {
        unsafe {
            delegated(
                file,
                |inner, methods| {
                    methods.xRead.map_or(ffi::SQLITE_IOERR, |read| {
                        read(inner, buffer, amount, offset)
                    })
                },
                ffi::SQLITE_IOERR,
            )
        }
    } else {
        unsafe { overlay_read(file, &*wrapper.overlay, buffer, amount, offset) }
    };
    if wrapper.rollback_view && offset == 0 && amount >= 20 && result == ffi::SQLITE_OK {
        // SAFETY: SQLite supplied a writable buffer of `amount >= 20` bytes it just filled.
        let header = unsafe { std::slice::from_raw_parts_mut(buffer.cast::<u8>(), 20) };
        header[18] = 1;
        header[19] = 1;
    }
    result
}

unsafe extern "C" fn file_write(
    file: *mut ffi::sqlite3_file,
    _buffer: *const c_void,
    _amount: c_int,
    _offset: ffi::sqlite3_int64,
) -> c_int {
    #[cfg(feature = "test-faults")]
    count(unsafe { &*wrapper(file).context }, |counters| {
        &counters.writes
    });
    let _ = file;
    ffi::SQLITE_READONLY
}

unsafe extern "C" fn file_truncate(
    file: *mut ffi::sqlite3_file,
    _size: ffi::sqlite3_int64,
) -> c_int {
    #[cfg(feature = "test-faults")]
    count(unsafe { &*wrapper(file).context }, |counters| {
        &counters.truncates
    });
    let _ = file;
    ffi::SQLITE_READONLY
}

unsafe extern "C" fn file_sync(file: *mut ffi::sqlite3_file, _flags: c_int) -> c_int {
    #[cfg(feature = "test-faults")]
    count(unsafe { &*wrapper(file).context }, |counters| {
        &counters.syncs
    });
    let _ = file;
    ffi::SQLITE_READONLY
}

unsafe extern "C" fn file_size(
    file: *mut ffi::sqlite3_file,
    size: *mut ffi::sqlite3_int64,
) -> c_int {
    let wrapper_ref = unsafe { wrapper(file) };
    if wrapper_ref.kind == FileKind::Wal {
        if !charge() {
            return ffi::SQLITE_IOERR;
        }
        tick();
        return match unsafe { &*wrapper_ref.wal }.metadata() {
            Ok(metadata) => {
                unsafe { *size = ffi::sqlite3_int64::try_from(metadata.len()).unwrap_or(0) };
                ffi::SQLITE_OK
            }
            Err(_) => ffi::SQLITE_IOERR,
        };
    }
    let code = unsafe {
        delegated(
            file,
            |inner, methods| {
                methods
                    .xFileSize
                    .map_or(ffi::SQLITE_IOERR, |get_size| get_size(inner, size))
            },
            ffi::SQLITE_IOERR,
        )
    };
    if code == ffi::SQLITE_OK && !wrapper_ref.overlay.is_null() {
        // The committed log may extend the database beyond the main file.
        let overlay = unsafe { &*wrapper_ref.overlay };
        let committed = i64::from(overlay.pages) * overlay.page_size as i64;
        unsafe { *size = (*size).max(committed) };
    }
    code
}

unsafe extern "C" fn file_lock(file: *mut ffi::sqlite3_file, level: c_int) -> c_int {
    if unsafe { wrapper(file) }.kind == FileKind::Wal {
        return ffi::SQLITE_OK;
    }
    unsafe {
        delegated(
            file,
            |inner, methods| {
                methods
                    .xLock
                    .map_or(ffi::SQLITE_IOERR, |lock| lock(inner, level))
            },
            ffi::SQLITE_IOERR,
        )
    }
}

unsafe extern "C" fn file_unlock(file: *mut ffi::sqlite3_file, level: c_int) -> c_int {
    if unsafe { wrapper(file) }.kind == FileKind::Wal {
        return ffi::SQLITE_OK;
    }
    unsafe {
        delegated(
            file,
            |inner, methods| {
                methods
                    .xUnlock
                    .map_or(ffi::SQLITE_IOERR, |unlock| unlock(inner, level))
            },
            ffi::SQLITE_IOERR,
        )
    }
}

unsafe extern "C" fn file_check_reserved(
    file: *mut ffi::sqlite3_file,
    result: *mut c_int,
) -> c_int {
    if unsafe { wrapper(file) }.kind == FileKind::Wal {
        unsafe { *result = 0 };
        return ffi::SQLITE_OK;
    }
    unsafe {
        delegated(
            file,
            |inner, methods| {
                methods
                    .xCheckReservedLock
                    .map_or(ffi::SQLITE_IOERR, |check| check(inner, result))
            },
            ffi::SQLITE_IOERR,
        )
    }
}

unsafe extern "C" fn file_control(
    file: *mut ffi::sqlite3_file,
    op: c_int,
    arg: *mut c_void,
) -> c_int {
    if unsafe { wrapper(file) }.kind == FileKind::Wal {
        return ffi::SQLITE_NOTFOUND;
    }
    unsafe {
        delegated(
            file,
            |inner, methods| {
                methods
                    .xFileControl
                    .map_or(ffi::SQLITE_NOTFOUND, |control| control(inner, op, arg))
            },
            ffi::SQLITE_NOTFOUND,
        )
    }
}

unsafe extern "C" fn file_sector_size(file: *mut ffi::sqlite3_file) -> c_int {
    if unsafe { wrapper(file) }.kind == FileKind::Wal {
        return 4096;
    }
    unsafe {
        delegated(
            file,
            |inner, methods| methods.xSectorSize.map_or(0, |sector| sector(inner)),
            0,
        )
    }
}

unsafe extern "C" fn file_device_characteristics(file: *mut ffi::sqlite3_file) -> c_int {
    if unsafe { wrapper(file) }.kind == FileKind::Wal {
        return 0;
    }
    unsafe {
        delegated(
            file,
            |inner, methods| {
                methods
                    .xDeviceCharacteristics
                    .map_or(0, |characteristics| characteristics(inner))
            },
            0,
        )
    }
}

/// The `-shm` sidecar must be absent or a regular file before the parent opens it by path, and
/// the open itself must name exactly that inode (or nothing): the expectation is checked by the
/// kernel-level `open` hook against the descriptor the parent obtains. The inode the path names
/// now is returned too: when the parent reuses a node an earlier connection of this process
/// already holds, no `open` happens at all, so the mapping it hands back is bound to this
/// identity instead (see [`file_shm_map`]).
fn shm_expectation(database: &CStr) -> Option<(ExpectGuard, Option<(u64, u64)>)> {
    let shm = sidecar_path(
        Path::new(std::ffi::OsStr::from_bytes(database.to_bytes())),
        "-shm",
    );
    if !charge() {
        return None;
    }
    tick();
    let identity = match std::fs::symlink_metadata(&shm) {
        Ok(metadata) if metadata.is_file() => Some((metadata.dev(), metadata.ino())),
        Ok(_) => return None,
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(_) => return None,
    };
    Some((
        ExpectGuard::register(shm.as_os_str().as_bytes().to_vec(), identity),
        identity,
    ))
}

unsafe extern "C" fn file_shm_map(
    file: *mut ffi::sqlite3_file,
    page: c_int,
    page_size: c_int,
    extend: c_int,
    result: *mut *mut c_void,
) -> c_int {
    let wrapper = unsafe { wrapper(file) };
    if wrapper.kind == FileKind::Wal {
        return IOERR_SHMMAP;
    }
    if extend != 0 {
        #[cfg(feature = "test-faults")]
        count(unsafe { &*wrapper.context }, |counters| &counters.writes);
        return ffi::SQLITE_READONLY;
    }
    #[cfg(feature = "test-faults")]
    count(unsafe { &*wrapper.context }, |counters| {
        &counters.shared_memory_maps
    });
    let (guard, expected) = if wrapper.shm_checked {
        (None, wrapper.shm_identity)
    } else {
        match shm_expectation(unsafe { &*wrapper.path }) {
            Some((guard, identity)) => (Some(guard), identity),
            None => return ffi::SQLITE_CANTOPEN,
        }
    };
    let mut code = unsafe {
        delegated(
            file,
            |inner, methods| {
                methods.xShmMap.map_or(ffi::SQLITE_READONLY, |map| {
                    map(inner, page, page_size, 0, result)
                })
            },
            ffi::SQLITE_READONLY,
        )
    };
    let first_check = guard.is_some();
    drop(guard);
    let mapped = unsafe { *result };
    if (code == ffi::SQLITE_OK || code == ffi::SQLITE_READONLY) && !mapped.is_null() {
        // The Unix parent reports SQLITE_READONLY with a pointer only for a node it opened
        // read-only (`readonly_shm`). SQLITE_OK with a pointer is a writable node: either a
        // connection of this process opened it for writing and this one would share it, or it is
        // unknown. A node an earlier connection of this process holds is reused without any
        // `open` or `stat` of the sidecar, so the pathname check above cannot vouch for it: the
        // mapping must itself have been made from the inode the sidecar path names now. Accept
        // only a node reported read-only whose mapping the kernel-level hook recorded as
        // PROT_READ and bound to that inode; anything else fails closed.
        let record = mapping_of(mapped);
        let bound = record.is_some_and(|map| map.identity.is_some() && map.identity == expected);
        if code == ffi::SQLITE_READONLY && bound && record.is_some_and(|map| !map.writable) {
            HOOK_STATS.readonly_maps.fetch_add(1, Ordering::Relaxed);
        } else {
            let counter = match record {
                None => &HOOK_STATS.unverified_maps_rejected,
                Some(map) if map.writable || code != ffi::SQLITE_READONLY => {
                    &HOOK_STATS.writable_maps_rejected
                }
                Some(_) => &HOOK_STATS.identity_rejected,
            };
            counter.fetch_add(1, Ordering::Relaxed);
            unsafe { *result = ptr::null_mut() };
            code = IOERR_SHMMAP;
        }
    }
    // Only a call that got through the parent and the checks above vouches for later ones: a
    // refused or failed first map is validated again, with a fresh expectation, on the next try.
    if first_check && (code == ffi::SQLITE_OK || code == ffi::SQLITE_READONLY) {
        wrapper.shm_checked = true;
        wrapper.shm_identity = expected;
    }
    code
}

unsafe extern "C" fn file_shm_lock(
    file: *mut ffi::sqlite3_file,
    offset: c_int,
    count: c_int,
    flags: c_int,
) -> c_int {
    if unsafe { wrapper(file) }.kind == FileKind::Wal {
        return ffi::SQLITE_READONLY;
    }
    unsafe {
        delegated(
            file,
            |inner, methods| {
                methods.xShmLock.map_or(ffi::SQLITE_READONLY, |lock| {
                    lock(inner, offset, count, flags)
                })
            },
            ffi::SQLITE_READONLY,
        )
    }
}

unsafe extern "C" fn file_shm_barrier(file: *mut ffi::sqlite3_file) {
    if unsafe { wrapper(file) }.kind == FileKind::Wal {
        return;
    }
    unsafe {
        delegated(
            file,
            |inner, methods| {
                if let Some(barrier) = methods.xShmBarrier {
                    barrier(inner);
                }
            },
            (),
        );
    }
}

unsafe extern "C" fn file_shm_unmap(file: *mut ffi::sqlite3_file, delete_flag: c_int) -> c_int {
    if unsafe { wrapper(file) }.kind == FileKind::Wal {
        return ffi::SQLITE_OK;
    }
    let result = unsafe {
        delegated(
            file,
            |inner, methods| {
                methods
                    .xShmUnmap
                    .map_or(ffi::SQLITE_READONLY, |unmap| unmap(inner, 0))
            },
            ffi::SQLITE_READONLY,
        )
    };
    // The parent has detached this connection from its node whatever the result: the next map
    // attaches again, to a node that may be one another connection kept alive across a sidecar
    // replacement, so what was validated for the previous attachment vouches for nothing.
    let wrapper = unsafe { wrapper(file) };
    wrapper.shm_checked = false;
    wrapper.shm_identity = None;
    if delete_flag != 0 {
        #[cfg(feature = "test-faults")]
        count(unsafe { &*wrapper.context }, |counters| &counters.deletes);
        return ffi::SQLITE_READONLY;
    }
    result
}

static READ_ONLY_IO: ffi::sqlite3_io_methods = ffi::sqlite3_io_methods {
    iVersion: 2,
    xClose: Some(file_close),
    xRead: Some(file_read),
    xWrite: Some(file_write),
    xTruncate: Some(file_truncate),
    xSync: Some(file_sync),
    xFileSize: Some(file_size),
    xLock: Some(file_lock),
    xUnlock: Some(file_unlock),
    xCheckReservedLock: Some(file_check_reserved),
    xFileControl: Some(file_control),
    xSectorSize: Some(file_sector_size),
    xDeviceCharacteristics: Some(file_device_characteristics),
    xShmMap: Some(file_shm_map),
    xShmLock: Some(file_shm_lock),
    xShmBarrier: Some(file_shm_barrier),
    xShmUnmap: Some(file_shm_unmap),
    xFetch: None,
    xUnfetch: None,
};
