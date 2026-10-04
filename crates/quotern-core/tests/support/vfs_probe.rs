use std::ffi::{CString, c_char};
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicUsize, Ordering};

use rusqlite::ffi;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VfsCounts {
    pub opens: usize,
    pub write_capable_opens: usize,
}

struct Context {
    parent: NonNull<ffi::sqlite3_vfs>,
    opens: AtomicUsize,
    write_capable_opens: AtomicUsize,
}

pub struct VfsProbe {
    name: CString,
    context: Box<Context>,
    vfs: Box<ffi::sqlite3_vfs>,
}

impl VfsProbe {
    pub fn new(name: &str) -> Result<Self, String> {
        let name = CString::new(name).map_err(|error| error.to_string())?;
        let parent = NonNull::new(unsafe { ffi::sqlite3_vfs_find(ptr::null()) })
            .ok_or_else(|| "default SQLite VFS unavailable".to_owned())?;
        let mut context = Box::new(Context {
            parent,
            opens: AtomicUsize::new(0),
            write_capable_opens: AtomicUsize::new(0),
        });
        let mut vfs = Box::new(unsafe { ptr::read(parent.as_ptr()) });
        vfs.pNext = ptr::null_mut();
        vfs.zName = name.as_ptr();
        vfs.pAppData = (&mut *context as *mut Context).cast();
        vfs.xOpen = Some(count_open);
        let result = unsafe { ffi::sqlite3_vfs_register(&mut *vfs, 0) };
        if result != ffi::SQLITE_OK {
            return Err(format!("SQLite VFS registration failed: {result}"));
        }
        Ok(Self { name, context, vfs })
    }

    pub fn name(&self) -> &CString {
        &self.name
    }

    pub fn counts(&self) -> VfsCounts {
        VfsCounts {
            opens: self.context.opens.load(Ordering::Relaxed),
            write_capable_opens: self.context.write_capable_opens.load(Ordering::Relaxed),
        }
    }
}

impl Drop for VfsProbe {
    fn drop(&mut self) {
        unsafe { ffi::sqlite3_vfs_unregister(&mut *self.vfs) };
    }
}

unsafe extern "C" fn count_open(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    file: *mut ffi::sqlite3_file,
    flags: std::ffi::c_int,
    out_flags: *mut std::ffi::c_int,
) -> std::ffi::c_int {
    // SAFETY: SQLite passes the registered VFS and its live pAppData to xOpen.
    let context = unsafe { &*((*vfs).pAppData.cast::<Context>()) };
    context.opens.fetch_add(1, Ordering::Relaxed);
    let write_flags =
        ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_CREATE | ffi::SQLITE_OPEN_DELETEONCLOSE;
    if flags & write_flags != 0 {
        context.write_capable_opens.fetch_add(1, Ordering::Relaxed);
    }
    // SAFETY: the delegated VFS is the original default VFS and receives SQLite's original arguments.
    let open = unsafe { (*context.parent.as_ptr()).xOpen }.expect("default SQLite VFS has xOpen");
    unsafe { open(context.parent.as_ptr(), name, file, flags, out_flags) }
}

/// Independent M2 observation of what the kernel actually granted (macOS arm64 only): descriptor
/// access modes from `F_GETFL`, mapping protections from `mach_vm_region`, and the parent's
/// successful `open`/`mmap` calls, plus its failing `fstat` calls, through exact, restorable chain
/// links on SQLite's own "unix" VFS. Nothing here reads the production hook statistics or the
/// flags a VFS merely requested. [`VfsProbe`] above stays the separate M1 detector of requested
/// `xOpen` flags.
///
/// Isolation: the chain links replace entries of a process-global table, so the probe is armed
/// in the test process itself (callers serialize on the VFS test guard) and not in a child. It is
/// bounded and restorable: every retained buffer is allocated before the first callback runs and
/// never grows inside one (a surplus event is dropped and recorded as a sticky overflow that fails
/// [`SyscallProbe::finish`] and every oracle), the lock is never held across a call to the previous
/// entry, return values and `errno` of that call are handed back unchanged, and `finish` restores
/// and verifies the exact saved entries (`Drop` is a best-effort backstop that discards a
/// restoration failure).
///
/// Ceiling: the live-descriptor sweep sees descriptors open at the instant of the sweep, and the
/// probe sees the parent's `open`/`mmap`/`fstat` entries; neither sees a transient descriptor
/// that a direct libc call opened and closed in between, nor a mapping made before the probe
/// started. Events from threads other than the arming one are kept and marked `foreign`; they
/// share the buffers, so unrelated activity of other threads counts against the bounds.
///
/// Participating acquisition: a native caller that reaches an entry through [`fetch_open`],
/// [`fetch_mmap`] or [`fetch_fstat`] (the `call_*` functions and the [`SyscallProbe`] methods are
/// built on them) registers with the armed probe before it reads the entry from the table, until
/// its call returns. The registration belongs to the [`Fetched`] handle alone: it holds the
/// generation that was armed at the fetch and whether its callback has been admitted, one thread
/// may hold any number of handles, dropping one releases only its own registration, and a
/// callback finds a registration only through the invocation in progress on its thread (restored
/// when the call returns), never through another handle or a plain call of that thread. At most
/// [`MAX_ACQUISITIONS`] registrations are pending at once: one more is refused, and the refusal
/// fails the observation. A registered fetch whose table read finds the entry already restored
/// (restoration got there between the registration and the read) is refused and fails the
/// observation too, never a clean finish without the call. Restoration waits for a registered
/// caller to run the callback it fetched, which records into the generation that was armed at the
/// fetch; a caller that has not got there within the quiescence bound fails `finish` loudly, and
/// its late call is forwarded unobserved, never recorded into a probe armed afterwards. The
/// ceiling is the participation: SQLite's own unix VFS, and any code that reads the table or
/// `xGetSystemCall` itself, fetches an entry without registering, so a callback fetched that way
/// before a restoration and invoked after it is forwarded unobserved (no probe armed) or
/// attributed to whichever probe is armed when it runs. An observation is complete for the calls
/// that were running or participating when it was finished, not for every acquisition in the
/// process.
///
/// Table access: SQLite's `xGetSystemCall`/`xSetSystemCall` read and write a plain pointer with
/// no synchronization, so every call of the probe to either (the saves, installations and
/// read-backs of `start`, the restoration, the participating fetch and [`SyscallProbe::table`])
/// is made holding one gate, never across a native call, a paused caller or a quiescence wait,
/// and recorded in an order witness ([`table_log`]); see `TableAccess`. The gate orders
/// participants only: a mutation is defined only while no raw reader (SQLite's own unix VFS, or
/// code calling `xGetSystemCall` itself) runs on another thread, which the suites hold as a
/// controlled premise (probes are armed under the VFS test guard, and the engine's own opens run
/// on the arming thread). No claim is made about arbitrary concurrent SQLite use.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub mod kernel {
    use std::cell::Cell;
    use std::ffi::{CStr, OsStr, c_char, c_int, c_void};
    use std::fmt;
    use std::fs::{File, OpenOptions};
    use std::marker::PhantomData;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex, MutexGuard, TryLockError};
    use std::time::Duration;

    use quotern_core::ingest::sqlite_ro::{OpenError, open_canonical};
    use rusqlite::ffi;

    const F_GETFL: c_int = 3;
    const O_ACCMODE: c_int = 3;
    const EIO: c_int = 5;
    const EBADF: c_int = 9;
    const O_RDWR: c_int = 2;
    const O_NOCTTY: c_int = 0x20000;
    pub const O_RDONLY: c_int = 0;
    pub const PROT_READ: c_int = 1;
    pub const PROT_WRITE: c_int = 2;
    const MAP_FAILED: usize = usize::MAX;

    /// Source file kinds, as indexes of [`SourceKeys`].
    pub const DB: usize = 0;
    pub const WAL: usize = 1;
    pub const SHM: usize = 2;
    pub const JOURNAL: usize = 3;
    const NAMES: [&str; 4] = ["database", "wal", "shm", "journal"];

    /// `(device, inode)` of the database, its WAL, SHM and journal (`None`: absent).
    pub type SourceKeys = [Option<(u64, u64)>; 4];

    unsafe extern "C" {
        fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
        // SDK: `int fstat(int, struct stat *)` (`sys/stat.h`), `struct stat` as [`Stat`].
        fn fstat(fd: c_int, buffer: *mut Stat) -> c_int;
        fn getdtablesize() -> c_int;
        fn __error() -> *mut c_int;
        // SDK: `pthread_t pthread_self(void)`, with `pthread_t` a pointer to an opaque struct.
        fn pthread_self() -> *mut c_void;
        fn posix_openpt(flags: c_int) -> c_int;
        fn grantpt(fd: c_int) -> c_int;
        fn unlockpt(fd: c_int) -> c_int;
        fn ptsname(fd: c_int) -> *const c_char;
        fn revoke(path: *const c_char) -> c_int;
        fn mprotect(address: *mut c_void, length: usize, protection: c_int) -> c_int;
        fn munmap(address: *mut c_void, length: usize) -> c_int;
        static mach_task_self_: u32;
        fn mach_vm_region(
            task: u32,
            address: *mut u64,
            size: *mut u64,
            flavor: c_int,
            info: *mut c_int,
            count: *mut u32,
            object: *mut u32,
        ) -> c_int;
        fn mach_port_deallocate(task: u32, name: u32) -> c_int;
    }

    /// One observation failure. `Copy`, so recording one never allocates inside a callback.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Fault {
        Fstat {
            fd: c_int,
            errno: c_int,
        },
        AccessMode {
            fd: c_int,
            errno: c_int,
        },
        EmptyMapping,
        MappingOverflow,
        Region {
            result: c_int,
            count: u32,
        },
        PortRelease {
            result: c_int,
        },
        /// A refused `open` kept the `errno` the probe planted before it, so a caller that retries
        /// that `errno` (SQLite's `robust_open` retries `EINTR` without bound) would never stop.
        RetryLoop {
            errno: c_int,
        },
        /// A registered fetch read an entry that restoration had already put back: its call would
        /// have run unobserved.
        EntryRestored {
            entry: &'static str,
        },
        /// A counter of the probe was released below zero: a registration was released twice or
        /// not taken.
        Accounting {
            counter: &'static str,
        },
    }

    impl fmt::Display for Fault {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Fstat { fd, errno } => write!(formatter, "fstat {fd}: errno {errno}"),
                Self::AccessMode { fd, errno } => {
                    write!(
                        formatter,
                        "F_GETFL failed for descriptor {fd}: errno {errno}"
                    )
                }
                Self::EmptyMapping => formatter.write_str("empty mapping"),
                Self::MappingOverflow => formatter.write_str("mapping range overflow"),
                Self::Region { result, count } => {
                    write!(
                        formatter,
                        "mapping not verified: result={result}, count={count}"
                    )
                }
                Self::PortRelease { result } => {
                    write!(formatter, "Mach port release failed: {result}")
                }
                Self::RetryLoop { errno } => write!(
                    formatter,
                    "refused open left errno {errno}: its caller would retry without bound"
                ),
                Self::EntryRestored { entry } => write!(
                    formatter,
                    "unix {entry:?} was restored before a registered fetch read it"
                ),
                Self::Accounting { counter } => {
                    write!(formatter, "probe counter {counter} released below zero")
                }
            }
        }
    }

    /// Identities of `database` and its sidecars, derived independently from `stat`.
    pub fn source_keys(database: &Path) -> Result<SourceKeys, String> {
        let mut keys = [None; 4];
        for (slot, suffix) in keys.iter_mut().zip(["", "-wal", "-shm", "-journal"]) {
            let path = PathBuf::from(format!("{}{suffix}", database.display()));
            match std::fs::metadata(&path) {
                Ok(metadata) => *slot = Some((metadata.dev(), metadata.ino())),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(format!("{}: {error}", path.display())),
            }
        }
        Ok(keys)
    }

    pub fn kind_of(keys: &SourceKeys, identity: Option<(u64, u64)>) -> Option<usize> {
        let identity = identity?;
        keys.iter().position(|key| *key == Some(identity))
    }

    #[derive(Clone, Copy, Debug)]
    pub struct FdSample {
        pub kind: usize,
        pub fd: c_int,
        /// Kernel access mode (`F_GETFL & O_ACCMODE`): 0 read-only, 1 write-only, 2 read-write.
        pub access: c_int,
    }

    /// Where, in the inspection of one descriptor, a test can close it under the sweep.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Gap {
        /// The first `F_GETFL` found the descriptor open; its `fstat` has not run.
        BeforeMetadata,
        /// `fstat` succeeded; the second `F_GETFL` has not run.
        BeforeAccess,
    }

    /// `struct stat` of this target, as the SDK declares it: `sys/stat.h` defines `struct stat` as
    /// `__DARWIN_STRUCT_STAT64` (`__DARWIN_64_BIT_INO_T`, what `fstat` fills on arm64), with
    /// `dev_t` `__int32_t`, `mode_t` and `nlink_t` `__uint16_t`, `__darwin_ino64_t` `__uint64_t`,
    /// `uid_t` and `gid_t` `__uint32_t`, `off_t` and `blkcnt_t` `__int64_t`, `blksize_t`
    /// `__int32_t`, and four `struct timespec` of two 8-byte words. libc 0.2.189 declares the same
    /// fields, in the same order and types (`unix/bsd/apple/mod.rs`, `struct stat`). The checks
    /// below pin the size (144) and the offsets of the fields that end each run of the layout.
    #[repr(C)]
    #[derive(Default)]
    #[allow(
        dead_code,
        reason = "all but the device and inode only give the kernel's layout"
    )]
    struct Stat {
        st_dev: i32,
        st_mode: u16,
        st_nlink: u16,
        st_ino: u64,
        st_uid: u32,
        st_gid: u32,
        st_rdev: i32,
        st_atimespec: [i64; 2],
        st_mtimespec: [i64; 2],
        st_ctimespec: [i64; 2],
        st_birthtimespec: [i64; 2],
        st_size: i64,
        st_blocks: i64,
        st_blksize: i32,
        st_flags: u32,
        st_gen: u32,
        st_lspare: i32,
        st_qspare: [i64; 2],
    }

    const _: () = assert!(
        size_of::<Stat>() == 144
            && std::mem::offset_of!(Stat, st_ino) == 8
            && std::mem::offset_of!(Stat, st_atimespec) == 32
            && std::mem::offset_of!(Stat, st_size) == 96
            && std::mem::offset_of!(Stat, st_blksize) == 112
            && std::mem::offset_of!(Stat, st_qspare) == 128
    );

    /// `F_GETFL`; `Err` carries the `errno` the kernel gave (`EBADF`: not open).
    fn access_flags(fd: c_int) -> Result<c_int, c_int> {
        // SAFETY: F_GETFL takes no argument and is defined for any integer.
        let flags = unsafe { fcntl(fd, F_GETFL) };
        if flags < 0 {
            // SAFETY: errno is thread-local.
            Err(unsafe { *__error() })
        } else {
            Ok(flags)
        }
    }

    /// Identity and kernel access mode of a live descriptor. The descriptor is only named to the
    /// kernel, never wrapped: it may be closed by another thread at any instant, and a `File`,
    /// `OwnedFd` or `BorrowedFd` over a closed descriptor breaks the contract of those types.
    /// `fstat` reports a closed one as `EBADF`, and writes the buffer only on success.
    fn inspect_fd(fd: c_int) -> Result<((u64, u64), c_int), Fault> {
        inspect_fd_between(fd, &mut |_| {})
    }

    fn inspect_fd_between(
        fd: c_int,
        between: &mut dyn FnMut(Gap),
    ) -> Result<((u64, u64), c_int), Fault> {
        between(Gap::BeforeMetadata);
        let mut stat = Stat::default();
        // SAFETY: `fd` is any integer; the buffer is the SDK's `struct stat`, checked above.
        if unsafe { fstat(fd, &raw mut stat) } != 0 {
            // SAFETY: errno is thread-local, read before anything else can change it.
            let errno = unsafe { *__error() };
            return Err(Fault::Fstat { fd, errno });
        }
        between(Gap::BeforeAccess);
        let flags = access_flags(fd).map_err(|errno| Fault::AccessMode { fd, errno })?;
        // The device is widened as `std` widens it (`st_dev as u64`), so identities compare equal
        // to those of `std::fs::Metadata`.
        Ok((
            (i64::from(stat.st_dev) as u64, stat.st_ino),
            flags & O_ACCMODE,
        ))
    }

    /// Every open descriptor of this process that names a source file, with its kernel access.
    pub fn live_source_fds(keys: &SourceKeys) -> Result<Vec<FdSample>, String> {
        live_source_fds_between(keys, &mut |_, _| {})
    }

    /// [`live_source_fds`] calling `between` at each [`Gap`] of every descriptor it inspects, so
    /// that a test can close one exactly there. Nothing else differs from the sweep.
    pub fn live_source_fds_between(
        keys: &SourceKeys,
        between: &mut dyn FnMut(Gap, c_int),
    ) -> Result<Vec<FdSample>, String> {
        // SAFETY: no arguments.
        let limit = unsafe { getdtablesize() };
        if limit <= 0 {
            return Err("descriptor limit unavailable".into());
        }
        let mut samples = Vec::new();
        for fd in 0..limit {
            match access_flags(fd) {
                Ok(_) => {}
                Err(EBADF) => continue,
                Err(errno) => return Err(Fault::AccessMode { fd, errno }.to_string()),
            }
            let (identity, access) = match inspect_fd_between(fd, &mut |gap| between(gap, fd)) {
                Ok(inspected) => inspected,
                // Another thread closed it after the check above: it is not a descriptor of the
                // instant any more. Only `EBADF` says so, and only while it is still closed; a
                // descriptor that is still open and cannot be inspected, or that fails any other
                // way, is an error, never skipped.
                Err(Fault::AccessMode { errno: EBADF, .. }) => continue,
                Err(fault @ Fault::Fstat { errno: EBADF, .. }) => {
                    if access_flags(fd) == Err(EBADF) {
                        continue;
                    }
                    return Err(fault.to_string());
                }
                Err(fault) => return Err(fault.to_string()),
            };
            if let Some(kind) = kind_of(keys, Some(identity)) {
                samples.push(FdSample { kind, fd, access });
            }
        }
        Ok(samples)
    }

    /// A descriptor that stays open (`F_GETFL` succeeds) while the kernel refuses to describe it
    /// (`fstat` fails with `EBADF`): the slave side of a pseudo-terminal after `revoke`. A real
    /// fault of the kind the sweep must report and never skip.
    pub struct RevokedDescriptor {
        _master: OwnedFd,
        slave: File,
    }

    impl RevokedDescriptor {
        pub fn new() -> Result<Self, String> {
            let failed = |what: &str| format!("{what}: {}", std::io::Error::last_os_error());
            // SAFETY: no pointers; the result is checked.
            let master = unsafe { posix_openpt(O_RDWR | O_NOCTTY) };
            if master < 0 {
                return Err(failed("posix_openpt"));
            }
            // SAFETY: `master` was just returned and is owned here exactly once.
            let master = unsafe { OwnedFd::from_raw_fd(master) };
            // SAFETY: `master` is a live pseudo-terminal master.
            if unsafe { grantpt(master.as_raw_fd()) } != 0 {
                return Err(failed("grantpt"));
            }
            // SAFETY: as above.
            if unsafe { unlockpt(master.as_raw_fd()) } != 0 {
                return Err(failed("unlockpt"));
            }
            // SAFETY: as above; the name is copied before anything else can reuse the buffer.
            let name = unsafe {
                let name = ptsname(master.as_raw_fd());
                if name.is_null() {
                    return Err(failed("ptsname"));
                }
                CStr::from_ptr(name).to_owned()
            };
            let slave = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(O_NOCTTY)
                .open(OsStr::from_bytes(name.to_bytes()))
                .map_err(|error| format!("open {name:?}: {error}"))?;
            // SAFETY: the name is NUL-terminated and names the slave this process owns.
            if unsafe { revoke(name.as_ptr()) } != 0 {
                return Err(failed("revoke"));
            }
            // The premise of every use: still open, no longer describable.
            // SAFETY: F_GETFL takes no argument.
            if unsafe { fcntl(slave.as_raw_fd(), F_GETFL) } < 0 {
                return Err("a revoked descriptor is no longer open".into());
            }
            match slave.metadata() {
                Err(error) if error.raw_os_error() == Some(EBADF) => {}
                other => return Err(format!("fstat of a revoked descriptor: {other:?}")),
            }
            Ok(Self {
                _master: master,
                slave,
            })
        }

        pub fn fd(&self) -> c_int {
            self.slave.as_raw_fd()
        }
    }

    /// Union of the kernel's current protections over `[pointer, pointer + length)`.
    fn region_protection(pointer: *mut c_void, length: usize) -> Result<c_int, Fault> {
        if length == 0 {
            return Err(Fault::EmptyMapping);
        }
        let end = (pointer as u64)
            .checked_add(length as u64)
            .ok_or(Fault::MappingOverflow)?;
        let mut cursor = pointer as u64;
        let mut protection = 0;
        while cursor < end {
            let mut start = cursor;
            let mut size = 0;
            // VM_REGION_BASIC_INFO_64: 36 bytes packed at 4, i.e. 9 words; word 0 is the current
            // protection (not max_protection).
            let mut info = [0_i32; 9];
            let mut count = 9_u32;
            let mut object = 0;
            // SAFETY: all out-pointers reference live locals of the documented sizes.
            let result = unsafe {
                mach_vm_region(
                    mach_task_self_,
                    &mut start,
                    &mut size,
                    9,
                    info.as_mut_ptr(),
                    &mut count,
                    &mut object,
                )
            };
            if object != 0 {
                // SAFETY: `object` is the port right the call returned.
                let released = unsafe { mach_port_deallocate(mach_task_self_, object) };
                if released != 0 {
                    return Err(Fault::PortRelease { result: released });
                }
            }
            if result != 0 || count != 9 || start > cursor || size == 0 {
                return Err(Fault::Region { result, count });
            }
            protection |= info[0];
            cursor = start.checked_add(size).ok_or(Fault::MappingOverflow)?;
        }
        Ok(protection)
    }

    /// The kernel's current protection over a live mapping.
    pub fn map_protection(pointer: *mut c_void, length: usize) -> Result<c_int, String> {
        region_protection(pointer, length).map_err(|fault| fault.to_string())
    }

    /// `mprotect`; `Err` carries `errno`. For a mapping this test made itself.
    pub fn set_protection(
        pointer: *mut c_void,
        length: usize,
        protection: c_int,
    ) -> Result<(), c_int> {
        // SAFETY: `pointer`/`length` name a mapping the caller owns; failure is reported, not UB.
        if unsafe { mprotect(pointer, length, protection) } == 0 {
            Ok(())
        } else {
            // SAFETY: errno is thread-local.
            Err(unsafe { *__error() })
        }
    }

    /// `munmap` of a mapping this test made itself.
    pub fn unmap(pointer: *mut c_void, length: usize) -> Result<(), c_int> {
        // SAFETY: as for `set_protection`.
        if unsafe { munmap(pointer, length) } == 0 {
            Ok(())
        } else {
            // SAFETY: errno is thread-local.
            Err(unsafe { *__error() })
        }
    }

    /// Every sampled source descriptor must be read-only.
    pub fn readonly_fd_oracle(samples: &[FdSample]) -> Result<(), String> {
        for sample in samples {
            if sample.access != O_RDONLY {
                return Err(format!(
                    "writable source descriptor: {} fd {} has kernel access {}",
                    NAMES[sample.kind], sample.fd, sample.access
                ));
            }
        }
        Ok(())
    }

    /// One successful `open` made through the parent's syscall entry.
    #[derive(Clone, Copy, Debug)]
    pub struct OpenEvent {
        pub identity: (u64, u64),
        pub fd: c_int,
        /// Kernel access mode of the descriptor the parent got back.
        pub access: c_int,
        /// Flags the parent requested at this link (before any hook below rewrote them).
        pub requested_flags: c_int,
        /// Made by a thread other than the one that armed the probe.
        pub foreign: bool,
    }

    /// One successful `mmap` made through the parent's syscall entry.
    #[derive(Clone, Copy, Debug)]
    pub struct MapEvent {
        pub identity: Option<(u64, u64)>,
        pub requested_protection: c_int,
        pub address: usize,
        pub length: usize,
        /// The kernel's current protection of the new mapping, queried right after the call.
        pub effective_protection: Option<c_int>,
        pub foreign: bool,
    }

    /// One `fstat` that failed at the parent's syscall entry, with the `errno` it returned with.
    #[derive(Clone, Copy, Debug)]
    pub struct FstatFailure {
        pub fd: c_int,
        pub errno: c_int,
        pub foreign: bool,
        /// Native metadata calls the independent physical observer saw during this very call;
        /// sampled (0 otherwise) only by a probe started with `start_fstat_only`.
        pub native_delta: u64,
    }

    /// One `open` that failed at the parent's syscall entry, with the `errno` it returned with.
    #[derive(Clone, Copy, Debug)]
    pub struct OpenFailure {
        pub errno: c_int,
        pub foreign: bool,
    }

    /// Retained-state ceilings of one probe, fixed when it starts.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Limits {
        pub opens: usize,
        pub maps: usize,
        pub fstat_failures: usize,
        pub open_failures: usize,
        pub errors: usize,
    }

    pub const DEFAULT_LIMITS: Limits = Limits {
        opens: 4096,
        maps: 4096,
        fstat_failures: 64,
        open_failures: 4096,
        errors: 16,
    };

    /// Most registrations of participating fetches pending at once in one probe. The callers are
    /// threads between a fetch and its call, a handful in any test; one more is refused and fails
    /// the observation, so the count cannot silently grow past what the proof accounts for.
    pub const MAX_ACQUISITIONS: usize = 64;

    #[derive(Clone, Debug, Default)]
    pub struct Events {
        pub opens: Vec<OpenEvent>,
        pub maps: Vec<MapEvent>,
        pub fstat_failures: Vec<FstatFailure>,
        /// Observation failures; any entry fails the test.
        pub errors: Vec<Fault>,
        /// Opens of the parent that failed (counted, and kept in `open_failures`).
        pub failed_opens: usize,
        pub open_failures: Vec<OpenFailure>,
        /// An event arrived with its buffer full and was dropped. Sticky: fails `finish` and
        /// every oracle, since the dropped event may have been the decisive one.
        pub overflowed: bool,
        /// Participating fetches refused at [`MAX_ACQUISITIONS`]. Sticky: fails `finish` and every
        /// oracle, since the refused caller's call was not observed.
        pub acquisitions_refused: usize,
    }

    impl Events {
        /// The observation itself was complete and error free.
        pub fn checked(&self) -> Result<(), String> {
            let mut problems = Vec::new();
            if !self.errors.is_empty() {
                let faults = self.errors.iter().map(Fault::to_string).collect::<Vec<_>>();
                problems.push(format!("observation errors: {faults:?}"));
            }
            if self.overflowed {
                problems.push("syscall probe overflow: events were dropped".to_owned());
            }
            if self.acquisitions_refused > 0 {
                problems.push(format!(
                    "{} participating fetch(es) refused at the acquisition limit",
                    self.acquisitions_refused
                ));
            }
            if problems.is_empty() {
                Ok(())
            } else {
                Err(problems.join("; "))
            }
        }

        pub fn opens_of(&self, keys: &SourceKeys, kind: usize) -> Vec<OpenEvent> {
            let selected = |event: &&OpenEvent| kind_of(keys, Some(event.identity)) == Some(kind);
            self.opens.iter().filter(selected).copied().collect()
        }

        pub fn maps_of(&self, keys: &SourceKeys, kind: usize) -> Vec<MapEvent> {
            let selected = |event: &&MapEvent| kind_of(keys, event.identity) == Some(kind);
            self.maps.iter().filter(selected).copied().collect()
        }

        /// Every successful parent open of a source file was read-only.
        pub fn readonly_open_oracle(&self, keys: &SourceKeys) -> Result<(), String> {
            self.checked()?;
            for event in &self.opens {
                if let Some(kind) = kind_of(keys, Some(event.identity))
                    && event.access != O_RDONLY
                {
                    return Err(format!(
                        "writable source open: {} fd {} has kernel access {}",
                        NAMES[kind], event.fd, event.access
                    ));
                }
            }
            Ok(())
        }

        /// Every successful shared-memory mapping asked the parent for read-only protection.
        pub fn requested_map_oracle(&self, keys: &SourceKeys) -> Result<(), String> {
            self.checked()?;
            for event in self.maps_of(keys, SHM) {
                if event.requested_protection & PROT_WRITE != 0 {
                    return Err(format!(
                        "writable shared-memory mapping requested: protection {}",
                        event.requested_protection
                    ));
                }
            }
            Ok(())
        }

        /// Every successful shared-memory mapping was granted without write access by the
        /// kernel, whatever was requested: the protection queried right after the call and,
        /// with `live`, the one the kernel reports now (the mappings must still exist).
        pub fn granted_map_oracle(&self, keys: &SourceKeys, live: bool) -> Result<(), String> {
            self.checked()?;
            for event in self.maps_of(keys, SHM) {
                let Some(granted) = event.effective_protection else {
                    return Err("shared-memory mapping protection unverified".into());
                };
                let now = if live {
                    map_protection(event.address as *mut c_void, event.length)?
                } else {
                    granted
                };
                if (granted | now) & PROT_WRITE != 0 {
                    return Err(format!(
                        "writable shared-memory mapping granted: kernel protection {granted} at the call, {now} now"
                    ));
                }
            }
            Ok(())
        }

        /// Requested and granted protections, at the call.
        pub fn readonly_map_oracle(&self, keys: &SourceKeys) -> Result<(), String> {
            self.requested_map_oracle(keys)?;
            self.granted_map_oracle(keys, false)
        }
    }

    pub type OpenFn = unsafe extern "C" fn(*const c_char, c_int, c_int) -> c_int;
    pub type MmapFn =
        unsafe extern "C" fn(*mut c_void, usize, c_int, c_int, c_int, i64) -> *mut c_void;
    pub type FstatFn = unsafe extern "C" fn(c_int, *mut c_void) -> c_int;

    #[derive(Clone, Copy)]
    struct Previous {
        open: OpenFn,
        mmap: MmapFn,
        fstat: FstatFn,
        /// Read the native observer's metadata count around each `fstat` (see [`FstatFailure`]).
        sample_native: bool,
        /// `errno` to plant immediately before each `open` of the parent, to model a stale value
        /// (see [`Fault::RetryLoop`]).
        stale_errno: Option<c_int>,
    }

    /// Consecutive refused opens that kept the planted `errno`, and the count that is a loop.
    static STALE_OPENS: AtomicU32 = AtomicU32::new(0);
    const STALE_OPEN_LIMIT: u32 = 32;
    const ENOENT: c_int = 2;

    /// How long restoring a probe waits for callbacks that were already running to finish.
    const QUIESCENCE: Duration = Duration::from_secs(10);

    struct Active {
        previous: Previous,
        events: Events,
        limits: Limits,
        /// `pthread_self` of the arming thread.
        owner: usize,
        /// Names this observation: a callback records only into the generation that admitted it,
        /// never into a later probe that happens to be armed when the callback ends.
        generation: u64,
        /// Callbacks admitted by this generation and not yet finished.
        in_flight: usize,
        /// Participating callers that began to fetch an entry under this generation and have not
        /// yet reached the callback they fetched.
        acquiring: usize,
        /// Restoration has put the entries back: no further callback is admitted.
        closing: bool,
        quiescence: Duration,
        /// Addresses of the callbacks this generation linked, by entry (`0`: not linked).
        hooks: [usize; 3],
    }

    impl Active {
        fn foreign(&self) -> bool {
            // SAFETY: pthread_self has no preconditions.
            let current = unsafe { pthread_self() } as usize;
            current != self.owner
        }

        fn fault(&mut self, fault: Fault) {
            if self.events.errors.len() < self.limits.errors {
                self.events.errors.push(fault);
            } else {
                self.events.overflowed = true;
            }
        }

        fn release_acquisition(&mut self) {
            match self.acquiring.checked_sub(1) {
                Some(left) => self.acquiring = left,
                None => self.fault(Fault::Accounting {
                    counter: "acquiring",
                }),
            }
        }

        fn release_callback(&mut self) {
            match self.in_flight.checked_sub(1) {
                Some(left) => self.in_flight = left,
                None => self.fault(Fault::Accounting {
                    counter: "in_flight",
                }),
            }
        }
    }

    /// Process-global because SQLite's syscall table is. The lock is never held across a call to
    /// the previous callback; restoration waits on [`QUIET`], which releases it.
    static ACTIVE: Mutex<Option<Active>> = Mutex::new(None);
    /// Signalled whenever an admitted callback finishes.
    static QUIET: Condvar = Condvar::new();
    static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);
    /// The entries below the latest probe, kept after it ended: a callback that had already
    /// read the table when the probe was restored still forwards its call (and records nothing).
    static FORWARD: Mutex<Option<Previous>> = Mutex::new(None);

    fn locked() -> MutexGuard<'static, Option<Active>> {
        ACTIVE.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// One admitted callback. Admission is counted in the generation that was armed, so
    /// restoration can wait for it; dropping it (after its event is recorded) reports it done.
    struct Call {
        previous: Previous,
        /// `None`: the call is forwarded and not observed (no probe was accepting callbacks, or
        /// the caller's acquisition belongs to a probe that has ended).
        generation: Option<u64>,
    }

    /// A participating caller's registration with the generation armed when it began to fetch.
    #[derive(Clone, Copy)]
    struct Claim {
        generation: u64,
        /// The fetched callback was admitted: counted in `in_flight` instead of `acquiring`.
        admitted: bool,
        /// The callbacks that generation linked (`0`: not linked); the entry a registered fetch
        /// reads must be one of them, or its call would run unobserved.
        hooks: [usize; 3],
    }

    thread_local! {
        /// The invocation in progress on this thread: the registration of the one [`Fetched`]
        /// handle being invoked, if it has one. Set for exactly the duration of that call and put
        /// back to what it was (an enclosing invocation, or none) when the call returns, so a
        /// callback never finds the registration of another handle or of a plain call.
        static INVOKING: Cell<Option<Claim>> = const { Cell::new(None) };
    }

    impl Call {
        fn enter() -> Option<Self> {
            let claim = INVOKING.with(Cell::get);
            if let Some(active) = locked().as_mut() {
                let owned = match claim {
                    // Fetched under this generation: admitted even while it restores, because
                    // restoration is waiting for exactly this call.
                    Some(claim) if claim.generation == active.generation => {
                        if !claim.admitted {
                            active.release_acquisition();
                            INVOKING.with(|cell| {
                                cell.set(Some(Claim {
                                    admitted: true,
                                    ..claim
                                }))
                            });
                        }
                        true
                    }
                    // Fetched under a probe that has ended: never recorded into this one.
                    Some(_) => false,
                    None => !active.closing,
                };
                if owned {
                    active.in_flight += 1;
                    return Some(Self {
                        previous: active.previous,
                        generation: Some(active.generation),
                    });
                }
            }
            let previous = (*FORWARD.lock().unwrap_or_else(|e| e.into_inner()))?;
            Some(Self {
                previous,
                generation: None,
            })
        }

        fn record(&self, change: impl FnOnce(&mut Active)) {
            let Some(generation) = self.generation else {
                return;
            };
            if let Some(active) = locked().as_mut()
                && active.generation == generation
            {
                change(active);
            }
        }
    }

    impl Drop for Call {
        fn drop(&mut self) {
            let Some(generation) = self.generation else {
                return;
            };
            if let Some(active) = locked().as_mut()
                && active.generation == generation
            {
                active.release_callback();
            }
            QUIET.notify_all();
        }
    }

    /// One [`Fetched`] handle's registration with the generation armed when it was fetched (none
    /// when no probe accepted callbacks then): the pending count it holds, or its admission, lives
    /// here and nowhere else. Dropping it gives back only its own pending count, and only to the
    /// generation it was taken from. `!Send`: it belongs to the thread that fetched.
    struct Registration {
        claim: Option<Claim>,
        _thread: PhantomData<*const ()>,
    }

    impl Registration {
        /// Registers with the armed generation, if one is accepting callbacks. Refused, with the
        /// refusal recorded as a failure of the observation, at [`MAX_ACQUISITIONS`] pending.
        fn begin() -> Result<Self, String> {
            let claim = match locked().as_mut().filter(|active| !active.closing) {
                None => None,
                Some(active) if active.acquiring >= MAX_ACQUISITIONS => {
                    active.events.acquisitions_refused += 1;
                    return Err(format!(
                        "{MAX_ACQUISITIONS} participating fetches are pending: this one is refused"
                    ));
                }
                Some(active) => {
                    active.acquiring += 1;
                    Some(Claim {
                        generation: active.generation,
                        admitted: false,
                        hooks: active.hooks,
                    })
                }
            };
            Ok(Self {
                claim,
                _thread: PhantomData,
            })
        }

        /// Checks the entry the table gave this fetch, read after registering: a linked entry
        /// that is no longer the generation's callback was restored in between, so its call would
        /// run unobserved. That fails the observation (if it still exists) and the fetch.
        fn verify(&self, index: usize, entry: usize) -> Result<(), String> {
            let Some(claim) = self.claim else {
                return Ok(());
            };
            let hook = claim.hooks[index];
            if hook == 0 || hook == entry {
                return Ok(());
            }
            if let Some(active) = locked().as_mut()
                && active.generation == claim.generation
            {
                active.fault(Fault::EntryRestored {
                    entry: ENTRY_NAMES[index],
                });
            }
            Err(format!(
                "unix {:?} was restored before the registered fetch read it: its call would not be observed",
                ENTRIES[index]
            ))
        }
    }

    impl Drop for Registration {
        fn drop(&mut self) {
            if let Some(claim) = self.claim
                && !claim.admitted
                && let Some(active) = locked().as_mut()
                && active.generation == claim.generation
            {
                active.release_acquisition();
            }
            QUIET.notify_all();
        }
    }

    /// The invocation of one handle on this thread, for the duration of its call: the callback
    /// finds this registration and no other. Dropping it puts the enclosing invocation back and
    /// hands the registration back as the callback left it (admitted or not).
    struct Invocation<'a> {
        registration: &'a mut Registration,
        enclosing: Option<Claim>,
    }

    impl<'a> Invocation<'a> {
        fn enter(registration: &'a mut Registration) -> Self {
            let enclosing = INVOKING.with(|cell| cell.replace(registration.claim));
            Self {
                registration,
                enclosing,
            }
        }
    }

    impl Drop for Invocation<'_> {
        fn drop(&mut self) {
            self.registration.claim = INVOKING.with(|cell| cell.replace(self.enclosing));
        }
    }

    /// Callbacks of the armed probe that started and have not finished.
    pub fn callbacks_in_flight() -> usize {
        locked().as_ref().map_or(0, |active| active.in_flight)
    }

    /// Participating callers of the armed probe that began to fetch an entry and have not yet
    /// reached its callback.
    pub fn acquisitions_pending() -> usize {
        locked().as_ref().map_or(0, |active| active.acquiring)
    }

    /// The armed probe is being restored and waits for its callbacks to finish.
    pub fn restoring() -> bool {
        locked().as_ref().is_some_and(|active| active.closing)
    }

    /// A probe is armed: its restoration has not yet taken its events.
    pub fn armed() -> bool {
        locked().is_some()
    }

    unsafe extern "C" fn observe_open(path: *const c_char, flags: c_int, mode: c_int) -> c_int {
        let Some(call) = Call::enter() else {
            // SAFETY: errno is thread-local. Unreachable once a probe has ever been armed.
            unsafe { *__error() = EIO };
            return -1;
        };
        let previous = call.previous;
        if call.generation.is_none() {
            // SAFETY: the arguments are exactly the caller's.
            return unsafe { (previous.open)(path, flags, mode) };
        }
        if let Some(stale) = previous.stale_errno {
            // SAFETY: errno is thread-local.
            unsafe { *__error() = stale };
        }
        // SAFETY: the arguments are exactly the parent's.
        let fd = unsafe { (previous.open)(path, flags, mode) };
        // SAFETY: errno is thread-local; the previous call's value is restored below.
        let mut errno = unsafe { *__error() };
        if let Some(stale) = previous.stale_errno {
            if fd < 0 && errno == stale {
                if STALE_OPENS.fetch_add(1, Ordering::Relaxed) + 1 > STALE_OPEN_LIMIT {
                    // Break the loop the caller would be in, and say so.
                    STALE_OPENS.store(0, Ordering::Relaxed);
                    call.record(|active| active.fault(Fault::RetryLoop { errno: stale }));
                    errno = ENOENT;
                }
            } else {
                STALE_OPENS.store(0, Ordering::Relaxed);
            }
        }
        if fd < 0 {
            call.record(|active| {
                active.events.failed_opens += 1;
                let foreign = active.foreign();
                if active.events.open_failures.len() < active.limits.open_failures {
                    active
                        .events
                        .open_failures
                        .push(OpenFailure { errno, foreign });
                } else {
                    active.events.overflowed = true;
                }
            });
        }
        if fd >= 0 {
            let inspected = inspect_fd(fd);
            call.record(|active| {
                let foreign = active.foreign();
                match inspected {
                    Ok((identity, access)) if active.events.opens.len() < active.limits.opens => {
                        active.events.opens.push(OpenEvent {
                            identity,
                            fd,
                            access,
                            requested_flags: flags,
                            foreign,
                        });
                    }
                    Ok(_) => active.events.overflowed = true,
                    Err(fault) => active.fault(fault),
                }
            });
        }
        // Finished (and reported so) before `errno` is set, so that nothing after it can change it.
        drop(call);
        unsafe { *__error() = errno };
        fd
    }

    unsafe extern "C" fn observe_mmap(
        address: *mut c_void,
        length: usize,
        protection: c_int,
        flags: c_int,
        fd: c_int,
        offset: i64,
    ) -> *mut c_void {
        let Some(call) = Call::enter() else {
            // SAFETY: errno is thread-local. Unreachable once a probe has ever been armed.
            unsafe { *__error() = EIO };
            return MAP_FAILED as *mut c_void;
        };
        let previous = call.previous;
        if call.generation.is_none() {
            // SAFETY: the arguments are exactly the caller's.
            return unsafe { (previous.mmap)(address, length, protection, flags, fd, offset) };
        }
        // SAFETY: errno is thread-local.
        let entry_errno = unsafe { *__error() };
        let identity = if fd >= 0 {
            match inspect_fd(fd) {
                Ok((identity, _)) => Some(identity),
                Err(fault) => {
                    call.record(|active| active.fault(fault));
                    None
                }
            }
        } else {
            None
        };
        unsafe { *__error() = entry_errno };
        // SAFETY: the arguments are exactly the parent's.
        let mapped = unsafe { (previous.mmap)(address, length, protection, flags, fd, offset) };
        let errno = unsafe { *__error() };
        if mapped as usize != MAP_FAILED {
            let effective = region_protection(mapped, length);
            call.record(|active| {
                let foreign = active.foreign();
                if active.events.maps.len() < active.limits.maps {
                    active.events.maps.push(MapEvent {
                        identity,
                        requested_protection: protection,
                        address: mapped as usize,
                        length,
                        effective_protection: effective.ok(),
                        foreign,
                    });
                } else {
                    active.events.overflowed = true;
                }
                if let Err(fault) = effective {
                    active.fault(fault);
                }
            });
        }
        drop(call);
        unsafe { *__error() = errno };
        mapped
    }

    unsafe extern "C" fn observe_fstat(fd: c_int, buffer: *mut c_void) -> c_int {
        let Some(call) = Call::enter() else {
            // SAFETY: errno is thread-local. Unreachable once a probe has ever been armed.
            unsafe { *__error() = EIO };
            return -1;
        };
        let previous = call.previous;
        if call.generation.is_none() {
            // SAFETY: the arguments are exactly the caller's.
            return unsafe { (previous.fstat)(fd, buffer) };
        }
        let before = if previous.sample_native {
            crate::support::physical_native::metadata_so_far()
        } else {
            0
        };
        // SAFETY: the arguments are exactly the parent's.
        let result = unsafe { (previous.fstat)(fd, buffer) };
        if result != 0 {
            // SAFETY: errno is thread-local; the previous call's value is restored below.
            let errno = unsafe { *__error() };
            let native_delta = if previous.sample_native {
                crate::support::physical_native::metadata_so_far().saturating_sub(before)
            } else {
                0
            };
            call.record(|active| {
                let foreign = active.foreign();
                if active.events.fstat_failures.len() < active.limits.fstat_failures {
                    active.events.fstat_failures.push(FstatFailure {
                        fd,
                        errno,
                        foreign,
                        native_delta,
                    });
                } else {
                    active.events.overflowed = true;
                }
            });
            drop(call);
            unsafe { *__error() = errno };
        }
        result
    }

    type RawCall = unsafe extern "C" fn();

    /// RAII link in the "unix" VFS's `open`/`mmap`/`fstat` syscall entries. Starting it first makes
    /// sure the production hooks are installed (they are the previous links, and are chained
    /// unchanged), so the probe sits above them and beside nothing else. `finish` restores the
    /// exact saved entries and verifies them; `Drop` is the panic backstop. `!Send`.
    pub struct SyscallProbe {
        parent: *mut ffi::sqlite3_vfs,
        saved: [RawCall; 3],
        linked: [bool; 3],
        restored: bool,
    }

    /// The entries this probe links, in installation order.
    const ENTRIES: [&CStr; 3] = [c"open", c"mmap", c"fstat"];

    /// Serializes every access to the "unix" VFS's syscall table. SQLite keeps each entry in a
    /// plain `pCurrent` pointer that `xGetSystemCall` reads and `xSetSystemCall` writes without any
    /// synchronization of its own (`sqlite3.c`, `unixGetSystemCall` and `unixSetSystemCall`), so a
    /// getter overlapping a setter is a data race whatever is done with the pointer afterwards,
    /// and checking the pointer after the read repairs nothing. The only code of this module that
    /// calls a getter or a setter is a method of [`TableAccess`], which holds this gate: the
    /// saves, installations and read-backs of `start`, the restoration and its read-backs, the
    /// participating fetch and [`SyscallProbe::table`].
    ///
    /// Lock order: the gate is never held while `ACTIVE`, `FORWARD` or a [`QUIET`] wait is taken
    /// or while a native syscall entry runs, and none of them is held while the gate is taken;
    /// the only lock taken inside it is the leaf [`TABLE_LOG`]. A paused caller (between a
    /// registration and its table read) holds no gate.
    ///
    /// Ceiling: the gate orders participants only. A raw reader (SQLite's own unix VFS reading
    /// `pCurrent` for an `xOpen`, or code calling `xGetSystemCall` itself) takes no gate, so a
    /// mutation here is defined only while no such reader runs on another thread. The suites hold
    /// that as a controlled premise: every test that arms a probe holds the VFS test guard, and
    /// the engine's own opens run on the arming thread; arbitrary concurrent SQLite use is not
    /// claimed safe.
    static TABLE: Mutex<()> = Mutex::new(());
    /// Acquisitions of the gate that found it held, ever. Incremented after [`TABLE_WAITING`], so
    /// a thread counted here is already counted as waiting.
    static TABLE_CONTENDED: AtomicU64 = AtomicU64::new(0);
    /// Threads blocked at the gate now.
    static TABLE_WAITING: AtomicUsize = AtomicUsize::new(0);

    /// One step of the order witness [`table_log`] keeps. `entry` indexes [`ENTRIES`]; an
    /// `address` of `0` is "no entry".
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum TableEvent {
        /// A thread acquired the gate.
        Entered,
        /// The thread that acquired the gate is about to give it back.
        Left,
        /// A getter returned `address`.
        Read { entry: usize, address: usize },
        /// A setter was asked for `address` and returned `code`.
        Wrote {
            entry: usize,
            address: usize,
            code: c_int,
        },
    }

    const TABLE_LOG_LIMIT: usize = 1024;

    /// Bounded and allocation free: appended to only while the gate is held, so its order is the
    /// order of the accesses; an event past the limit is dropped and the loss is sticky.
    struct TableLog {
        events: [TableEvent; TABLE_LOG_LIMIT],
        len: usize,
        overflowed: bool,
    }

    static TABLE_LOG: Mutex<TableLog> = Mutex::new(TableLog {
        events: [TableEvent::Left; TABLE_LOG_LIMIT],
        len: 0,
        overflowed: false,
    });

    fn record(event: TableEvent) {
        let mut log = TABLE_LOG.lock().unwrap_or_else(|e| e.into_inner());
        if log.len < TABLE_LOG_LIMIT {
            let len = log.len;
            log.events[len] = event;
            log.len += 1;
        } else {
            log.overflowed = true;
        }
    }

    /// The table accesses since [`clear_table_log`], in the order they happened; an error when
    /// the bound was exceeded (events were lost).
    pub fn table_log() -> Result<Vec<TableEvent>, String> {
        let log = TABLE_LOG.lock().unwrap_or_else(|e| e.into_inner());
        if log.overflowed {
            return Err(format!(
                "more than {TABLE_LOG_LIMIT} table events: some were lost"
            ));
        }
        Ok(log.events[..log.len].to_vec())
    }

    pub fn clear_table_log() {
        let mut log = TABLE_LOG.lock().unwrap_or_else(|e| e.into_inner());
        log.len = 0;
        log.overflowed = false;
    }

    /// Acquisitions of the gate, ever, that had to wait for another holder.
    pub fn table_contentions() -> u64 {
        TABLE_CONTENDED.load(Ordering::SeqCst)
    }

    /// Threads blocked at the gate now.
    pub fn table_waiting() -> usize {
        TABLE_WAITING.load(Ordering::SeqCst)
    }

    /// Possession of the gate: the only way to call a syscall-table getter or setter. `!Send`.
    struct TableAccess {
        _gate: MutexGuard<'static, ()>,
    }

    impl TableAccess {
        fn lock() -> Self {
            let gate = match TABLE.try_lock() {
                Ok(gate) => gate,
                Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
                Err(TryLockError::WouldBlock) => {
                    TABLE_WAITING.fetch_add(1, Ordering::SeqCst);
                    TABLE_CONTENDED.fetch_add(1, Ordering::SeqCst);
                    let gate = TABLE.lock().unwrap_or_else(|e| e.into_inner());
                    TABLE_WAITING.fetch_sub(1, Ordering::SeqCst);
                    gate
                }
            };
            record(TableEvent::Entered);
            Self { _gate: gate }
        }

        /// `xGetSystemCall`.
        ///
        /// # Safety
        /// `parent` is the verified "unix" VFS and has a getter.
        unsafe fn get(
            &self,
            parent: *mut ffi::sqlite3_vfs,
            name: &CStr,
        ) -> ffi::sqlite3_syscall_ptr {
            // SAFETY: the caller verified the VFS and its getter; the gate is held.
            let call = unsafe {
                (*parent)
                    .xGetSystemCall
                    .and_then(|get| get(parent, name.as_ptr()))
            };
            record(TableEvent::Read {
                entry: entry_index(name),
                address: address(call).unwrap_or(0),
            });
            call
        }

        /// `xSetSystemCall`.
        ///
        /// # Safety
        /// `parent` is the verified "unix" VFS and has a setter.
        unsafe fn set(
            &self,
            parent: *mut ffi::sqlite3_vfs,
            name: &CStr,
            call: ffi::sqlite3_syscall_ptr,
        ) -> c_int {
            // SAFETY: the caller verified the VFS and its setter; the gate is held.
            let code = unsafe {
                (*parent)
                    .xSetSystemCall
                    .map_or(ffi::SQLITE_MISUSE, |set| set(parent, name.as_ptr(), call))
            };
            record(TableEvent::Wrote {
                entry: entry_index(name),
                address: address(call).unwrap_or(0),
                code,
            });
            code
        }
    }

    impl Drop for TableAccess {
        fn drop(&mut self) {
            record(TableEvent::Left);
        }
    }

    fn entry_index(name: &CStr) -> usize {
        ENTRIES
            .iter()
            .position(|entry| *entry == name)
            .unwrap_or(usize::MAX)
    }

    /// The gate, held by a test: every participating access of this module waits until it is
    /// dropped. The holder must not call into this module's table accessors meanwhile, except
    /// through [`Self::table`]. `!Send`: the thread that took it gives it back.
    pub struct HeldTable {
        access: TableAccess,
    }

    pub fn hold_table() -> HeldTable {
        HeldTable {
            access: TableAccess::lock(),
        }
    }

    impl HeldTable {
        /// Addresses of the unix VFS's `open`, `mmap` and `fstat` entries right now.
        pub fn table(&self) -> Result<[usize; 3], String> {
            read_table(&self.access, unix_parent()?)
        }
    }

    fn read_table(
        access: &TableAccess,
        parent: *mut ffi::sqlite3_vfs,
    ) -> Result<[usize; 3], String> {
        let mut table = [0; 3];
        for (slot, name) in table.iter_mut().zip(ENTRIES) {
            // SAFETY: `parent` was verified by `unix_parent`.
            *slot = address(unsafe { access.get(parent, name) })
                .ok_or_else(|| format!("unix {name:?} unavailable"))?;
        }
        Ok(table)
    }

    fn address(call: ffi::sqlite3_syscall_ptr) -> Option<usize> {
        call.map(|call| call as usize)
    }

    fn unix_parent() -> Result<*mut ffi::sqlite3_vfs, String> {
        // SAFETY: the name is NUL-terminated; SQLite returns a stable VFS or NULL.
        let parent = unsafe { ffi::sqlite3_vfs_find(c"unix".as_ptr()) };
        if parent.is_null() {
            return Err("unix VFS unavailable".into());
        }
        // SAFETY: `parent` is a registered VFS.
        let (name, version, has_calls) = unsafe {
            (
                CStr::from_ptr((*parent).zName).to_bytes() == b"unix",
                (*parent).iVersion,
                (*parent).xGetSystemCall.is_some() && (*parent).xSetSystemCall.is_some(),
            )
        };
        if !name || version < 3 || !has_calls {
            return Err("the named unix VFS has no system-call table".into());
        }
        Ok(parent)
    }

    /// Registers the permanent production VFS and installs its syscall hooks into the "unix"
    /// VFS's table. They are never removed, so what a test reads as "the original entries"
    /// before this ran is not what is restored after any probe: call it before sampling a
    /// baseline. The open that does it fails before any source is touched.
    pub fn initialize_production_hooks() -> Result<(), String> {
        // Through a guaranteed-absent absolute path.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let absent = std::env::temp_dir()
            .join(format!("quotern-absent-{}-{nanos}", std::process::id()))
            .join("absent.db");
        match open_canonical(&absent) {
            Err(OpenError::Sqlite(code)) if code & 0xff == ffi::SQLITE_CANTOPEN => {}
            other => return Err(format!("hook initialization open: {:?}", other.map(|_| ()))),
        }
        if absent.exists() {
            return Err("hook initialization created its scratch path".into());
        }
        // SAFETY: the name is NUL-terminated.
        if unsafe { ffi::sqlite3_vfs_find(c"quotern-ro".as_ptr()) }.is_null() {
            return Err("quotern-ro VFS is not registered".into());
        }
        Ok(())
    }

    /// The entry the "unix" VFS would call right now, read from the table as SQLite does, under
    /// the table gate (released before the caller does anything with the entry).
    fn installed_entry(name: &CStr) -> Result<RawCall, String> {
        let parent = unix_parent()?;
        let table = TableAccess::lock();
        // SAFETY: `parent` was verified above.
        unsafe { table.get(parent, name) }.ok_or_else(|| format!("unix {name:?} unavailable"))
    }

    /// An installed entry fetched by a participating caller. The registration with the armed
    /// probe starts before the table is read and lasts until this is dropped, so a restoration
    /// that begins in between waits for [`Self::invoke`]. Pausing between the fetch and the
    /// invocation is the point of the split. The handle owns its registration: any number may be
    /// held by one thread, and each releases only its own.
    pub struct Fetched<F> {
        call: F,
        address: usize,
        registration: Registration,
    }

    const ENTRY_NAMES: [&str; 3] = ["open", "mmap", "fstat"];

    /// Registers, runs `before_read` (a test's deterministic pause between the registration and
    /// the table read), reads entry `index` and checks it.
    fn fetch<F>(
        index: usize,
        before_read: impl FnOnce(),
        convert: impl FnOnce(RawCall) -> F,
    ) -> Result<Fetched<F>, String> {
        let registration = Registration::begin()?;
        before_read();
        let call = installed_entry(ENTRIES[index])?;
        registration.verify(index, call as usize)?;
        Ok(Fetched {
            call: convert(call),
            address: call as usize,
            registration,
        })
    }

    /// Fetches the installed `open` entry as SQLite's unix VFS does.
    pub fn fetch_open() -> Result<Fetched<OpenFn>, String> {
        fetch_open_between(|| {})
    }

    /// [`fetch_open`], running `before_read` after the registration and before the table read.
    pub fn fetch_open_between(before_read: impl FnOnce()) -> Result<Fetched<OpenFn>, String> {
        // SAFETY: the unix VFS documents this C signature for this entry.
        fetch(0, before_read, |call| unsafe {
            std::mem::transmute::<RawCall, OpenFn>(call)
        })
    }

    /// Fetches the installed `mmap` entry as SQLite's unix VFS does.
    pub fn fetch_mmap() -> Result<Fetched<MmapFn>, String> {
        fetch_mmap_between(|| {})
    }

    /// [`fetch_mmap`], running `before_read` after the registration and before the table read.
    pub fn fetch_mmap_between(before_read: impl FnOnce()) -> Result<Fetched<MmapFn>, String> {
        // SAFETY: the unix VFS documents this C signature for this entry.
        fetch(1, before_read, |call| unsafe {
            std::mem::transmute::<RawCall, MmapFn>(call)
        })
    }

    /// Fetches the installed `fstat` entry as SQLite's unix VFS does.
    pub fn fetch_fstat() -> Result<Fetched<FstatFn>, String> {
        fetch_fstat_between(|| {})
    }

    /// [`fetch_fstat`], running `before_read` after the registration and before the table read.
    pub fn fetch_fstat_between(before_read: impl FnOnce()) -> Result<Fetched<FstatFn>, String> {
        // SAFETY: the unix VFS documents this C signature for this entry.
        fetch(2, before_read, |call| unsafe {
            std::mem::transmute::<RawCall, FstatFn>(call)
        })
    }

    impl Fetched<OpenFn> {
        /// Calls the fetched entry; `(fd, errno)`.
        pub fn invoke(mut self, path: &CStr, flags: c_int, mode: c_int) -> (c_int, c_int) {
            let call = self.call;
            let _invocation = Invocation::enter(&mut self.registration);
            // SAFETY: the path is valid; errno is thread-local.
            unsafe {
                *__error() = 0;
                (call(path.as_ptr(), flags, mode), *__error())
            }
        }
    }

    impl Fetched<MmapFn> {
        /// Calls the fetched entry; `(pointer, errno)` with a failed map as `usize::MAX`. A null
        /// hint address lets the kernel choose, and a bad descriptor makes the call fail.
        pub fn invoke(
            mut self,
            length: usize,
            protection: c_int,
            flags: c_int,
            fd: c_int,
            offset: i64,
        ) -> (usize, c_int) {
            let call = self.call;
            let _invocation = Invocation::enter(&mut self.registration);
            // SAFETY: as above; the call fails or maps, it never faults.
            let (mapped, errno) = unsafe {
                *__error() = 0;
                (
                    call(std::ptr::null_mut(), length, protection, flags, fd, offset),
                    *__error(),
                )
            };
            (mapped as usize, errno)
        }
    }

    impl Fetched<FstatFn> {
        /// Calls the fetched entry; `(result, errno)`.
        pub fn invoke(mut self, fd: c_int) -> (c_int, c_int) {
            let call = self.call;
            let _invocation = Invocation::enter(&mut self.registration);
            let mut buffer = Stat::default();
            // SAFETY: as above; the buffer is the SDK's `struct stat`.
            unsafe {
                *__error() = 0;
                (call(fd, (&raw mut buffer).cast()), *__error())
            }
        }
    }

    /// Calls the installed `open` entry as SQLite's unix VFS does, from any thread; `(fd, errno)`.
    pub fn call_open(path: &CStr, flags: c_int, mode: c_int) -> Result<(c_int, c_int), String> {
        Ok(fetch_open()?.invoke(path, flags, mode))
    }

    /// Calls the installed `mmap` entry as SQLite's unix VFS does, from any thread;
    /// `(pointer, errno)` with a failed map as `usize::MAX`.
    pub fn call_mmap(
        length: usize,
        protection: c_int,
        flags: c_int,
        fd: c_int,
        offset: i64,
    ) -> Result<(usize, c_int), String> {
        Ok(fetch_mmap()?.invoke(length, protection, flags, fd, offset))
    }

    /// Calls the installed `fstat` entry as SQLite's unix VFS does, from any thread;
    /// `(result, errno)`.
    pub fn call_fstat(fd: c_int) -> Result<(c_int, c_int), String> {
        Ok(fetch_fstat()?.invoke(fd))
    }

    impl SyscallProbe {
        /// Addresses of the unix VFS's `open`, `mmap` and `fstat` entries right now.
        pub fn table() -> Result<[usize; 3], String> {
            let parent = unix_parent()?;
            let access = TableAccess::lock();
            read_table(&access, parent)
        }

        pub fn start() -> Result<Self, String> {
            Self::start_with(DEFAULT_LIMITS)
        }

        /// Like [`Self::start`], but links only the parent's `fstat` entry (failures and their
        /// `errno`), so the probe itself issues no `fstat` or `fcntl` on a source descriptor and
        /// a native observer stays comparable with the charged work.
        pub fn start_fstat_only() -> Result<Self, String> {
            Self::start_linked(DEFAULT_LIMITS, [false, false, true], None, || {})
        }

        /// [`Self::start_fstat_only`] with explicit retained-state ceilings.
        pub fn start_fstat_only_with(limits: Limits) -> Result<Self, String> {
            Self::start_linked(limits, [false, false, true], None, || {})
        }

        /// Links only `open`, planting `errno` right before each open of the parent: a refused
        /// open that leaves it behind is a [`Fault::RetryLoop`] (and the loop is broken after a
        /// bounded number of tries instead of spinning).
        pub fn start_stale_errno(errno: c_int) -> Result<Self, String> {
            STALE_OPENS.store(0, Ordering::Relaxed);
            Self::start_linked(DEFAULT_LIMITS, [true, false, false], Some(errno), || {})
        }

        /// [`Self::start`], running `before_install` after the probe is armed and before its
        /// entries are installed (a test's deterministic pause around the installation).
        pub fn start_paused_before_install(before_install: impl FnOnce()) -> Result<Self, String> {
            Self::start_linked(DEFAULT_LIMITS, [true; 3], None, before_install)
        }

        /// Starts with explicit retained-state ceilings, all allocated here.
        pub fn start_with(limits: Limits) -> Result<Self, String> {
            Self::start_linked(limits, [true; 3], None, || {})
        }

        fn start_linked(
            limits: Limits,
            links: [bool; 3],
            stale_errno: Option<c_int>,
            before_install: impl FnOnce(),
        ) -> Result<Self, String> {
            initialize_production_hooks()?;
            let parent = unix_parent()?;
            let saved = {
                let table = TableAccess::lock();
                // SAFETY: as above.
                unsafe {
                    [
                        table.get(parent, c"open").ok_or("unix open unavailable")?,
                        table.get(parent, c"mmap").ok_or("unix mmap unavailable")?,
                        table
                            .get(parent, c"fstat")
                            .ok_or("unix fstat unavailable")?,
                    ]
                }
            };
            // SAFETY: the unix VFS documents exactly these C signatures for these entries.
            let previous = unsafe {
                Previous {
                    open: std::mem::transmute::<RawCall, OpenFn>(saved[0]),
                    mmap: std::mem::transmute::<RawCall, MmapFn>(saved[1]),
                    fstat: std::mem::transmute::<RawCall, FstatFn>(saved[2]),
                    sample_native: links == [false, false, true],
                    stale_errno,
                }
            };
            let observers = [
                observe_open as OpenFn as usize,
                observe_mmap as MmapFn as usize,
                observe_fstat as FstatFn as usize,
            ];
            let mut linked_hooks = [0; 3];
            for ((slot, observer), linked) in linked_hooks.iter_mut().zip(observers).zip(links) {
                if linked {
                    *slot = observer;
                }
            }
            {
                let mut active = ACTIVE.lock().unwrap_or_else(|e| e.into_inner());
                if active.is_some() {
                    return Err("a syscall probe is already active".into());
                }
                *active = Some(Active {
                    previous,
                    events: Events {
                        opens: Vec::with_capacity(limits.opens),
                        maps: Vec::with_capacity(limits.maps),
                        fstat_failures: Vec::with_capacity(limits.fstat_failures),
                        errors: Vec::with_capacity(limits.errors),
                        failed_opens: 0,
                        open_failures: Vec::with_capacity(limits.open_failures),
                        overflowed: false,
                        acquisitions_refused: 0,
                    },
                    limits,
                    // SAFETY: pthread_self has no preconditions.
                    owner: unsafe { pthread_self() } as usize,
                    generation: NEXT_GENERATION.fetch_add(1, Ordering::Relaxed),
                    in_flight: 0,
                    acquiring: 0,
                    closing: false,
                    quiescence: QUIESCENCE,
                    hooks: linked_hooks,
                });
                *FORWARD.lock().unwrap_or_else(|e| e.into_inner()) = Some(previous);
            }
            let mut probe = Self {
                parent,
                saved,
                linked: links,
                restored: false,
            };
            // SAFETY: erased only at SQLite's registration boundary; the signatures match.
            let hooks = unsafe {
                [
                    std::mem::transmute::<OpenFn, RawCall>(observe_open),
                    std::mem::transmute::<MmapFn, RawCall>(observe_mmap),
                    std::mem::transmute::<FstatFn, RawCall>(observe_fstat),
                ]
            };
            before_install();
            let mut refused = None;
            {
                let table = TableAccess::lock();
                for ((name, hook), linked) in ENTRIES.into_iter().zip(hooks).zip(links) {
                    if !linked {
                        continue;
                    }
                    // SAFETY: `parent` was verified above.
                    let installed = unsafe {
                        table.set(parent, name, Some(hook)) == ffi::SQLITE_OK
                            && address(table.get(parent, name)) == Some(hook as usize)
                    };
                    if !installed {
                        refused = Some(name);
                        break;
                    }
                }
            }
            // The gate is released: restoring takes it again.
            if let Some(name) = refused {
                let restored = probe.restore();
                return Err(format!(
                    "could not install the {name:?} probe ({restored:?})"
                ));
            }
            Ok(probe)
        }

        /// Events so far (the probe stays installed).
        pub fn events(&self) -> Events {
            ACTIVE
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .map(|active| active.events.clone())
                .unwrap_or_default()
        }

        /// How long restoration waits for callbacks that were already running when it began; a
        /// callback still running then makes `finish` fail instead of losing its event.
        pub fn set_quiescence(&self, quiescence: Duration) {
            if let Some(active) = locked().as_mut() {
                active.quiescence = quiescence;
            }
        }

        /// Fails unless the entry a participating caller fetched is this probe's own callback.
        fn own(name: &CStr, address: usize, hook: usize) -> Result<(), String> {
            if address == hook {
                Ok(())
            } else {
                Err(format!("unix {name:?} is not this probe's callback"))
            }
        }

        /// Calls the installed `open` entry exactly as SQLite's unix VFS does; `(fd, errno)`.
        pub fn open(
            &self,
            path: &CStr,
            flags: c_int,
            mode: c_int,
        ) -> Result<(c_int, c_int), String> {
            let fetched = fetch_open()?;
            Self::own(c"open", fetched.address, observe_open as OpenFn as usize)?;
            Ok(fetched.invoke(path, flags, mode))
        }

        /// Calls the installed `mmap` entry exactly as SQLite's unix VFS does; `(pointer, errno)`
        /// with a failed map as `usize::MAX`.
        pub fn mmap(
            &self,
            length: usize,
            protection: c_int,
            flags: c_int,
            fd: c_int,
            offset: i64,
        ) -> Result<(usize, c_int), String> {
            let fetched = fetch_mmap()?;
            Self::own(c"mmap", fetched.address, observe_mmap as MmapFn as usize)?;
            Ok(fetched.invoke(length, protection, flags, fd, offset))
        }

        /// Calls the installed `fstat` entry exactly as SQLite's unix VFS does; `(result, errno)`.
        pub fn fstat(&self, fd: c_int) -> Result<(c_int, c_int), String> {
            let fetched = fetch_fstat()?;
            Self::own(c"fstat", fetched.address, observe_fstat as FstatFn as usize)?;
            Ok(fetched.invoke(fd))
        }

        fn restore(&mut self) -> Result<Events, String> {
            if self.restored {
                return Ok(Events::default());
            }
            let mut problems = Vec::new();
            {
                let table = TableAccess::lock();
                // Last installed first; the exact saved entries, never NULL (NULL resets defaults
                // and would erase the production hooks).
                for ((name, saved), linked) in
                    ENTRIES.into_iter().zip(self.saved).zip(self.linked).rev()
                {
                    if !linked {
                        continue;
                    }
                    // SAFETY: `parent` was verified when the probe started and is never
                    // unregistered.
                    let (code, now) = unsafe {
                        (
                            table.set(self.parent, name, Some(saved)),
                            address(table.get(self.parent, name)),
                        )
                    };
                    if code != ffi::SQLITE_OK || now != Some(saved as usize) {
                        problems.push(format!("{name:?}: set={code}, restored={now:?}"));
                    }
                }
            }
            self.restored = true;
            // The entries are back, so no new callback arrives through the table. Callers that
            // fetched an entry before (running its callback, or paused between the fetch and the
            // call) are waited for with the lock released while waiting, and record into this
            // generation before it is taken; one that does not get there in time fails the
            // restoration loudly. A callback fetched without registering (SQLite's own, see the
            // module ceiling) that reads the table just before still forwards its call unobserved.
            let mut guard = locked();
            let quiescence = guard.as_ref().map_or(Duration::ZERO, |a| a.quiescence);
            if let Some(active) = guard.as_mut() {
                active.closing = true;
            }
            let (mut guard, _) = QUIET
                .wait_timeout_while(guard, quiescence, |active| {
                    active
                        .as_ref()
                        .is_some_and(|active| active.in_flight > 0 || active.acquiring > 0)
                })
                .unwrap_or_else(|e| e.into_inner());
            let active = guard.take();
            drop(guard);
            if let Some(active) = &active {
                if active.in_flight > 0 {
                    problems.push(format!(
                        "{} probe callback(s) still running after {quiescence:?}: their events are lost",
                        active.in_flight
                    ));
                }
                if active.acquiring > 0 {
                    problems.push(format!(
                        "{} native call(s) fetched a probe entry before restoration and had not run it after {quiescence:?}: their events are not observed",
                        active.acquiring
                    ));
                }
            }
            let events = active.map(|active| active.events).unwrap_or_default();
            if problems.is_empty() {
                Ok(events)
            } else {
                Err(problems.join("; "))
            }
        }

        /// Restores the exact previous entries, verifies them, and returns the events; an
        /// observation error or an overflow fails here, after the restoration.
        pub fn finish(mut self) -> Result<Events, String> {
            let events = self.restore()?;
            events.checked()?;
            Ok(events)
        }
    }

    /// The failure of the last restoration a [`SyscallProbe`] drop had to discard, since `Drop`
    /// cannot return one. A probe that was finished, or whose restoration succeeded when it was
    /// dropped, leaves nothing here.
    static DISCARDED_RESTORATION: Mutex<Option<String>> = Mutex::new(None);

    /// Takes (and clears) the failure that the last dropped probe's restoration discarded.
    pub fn take_discarded_restoration() -> Option<String> {
        DISCARDED_RESTORATION
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }

    impl Drop for SyscallProbe {
        fn drop(&mut self) {
            if let Err(problem) = self.restore() {
                *DISCARDED_RESTORATION
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = Some(problem);
            }
        }
    }
}
