use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};

use crate::domain::PassCounters;
use crate::ingest::fs::SourceFs;
use crate::limits::MAX_PATH_BYTES;

/// The nearest existing directory at or above the data root, with the identity it had when the
/// roots were validated. The store creates and opens everything beneath a handle bound to it, so
/// a path swapped afterwards is refused instead of followed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataAnchor {
    pub path: PathBuf,
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Debug)]
pub struct CanonicalRoots {
    pub source: PathBuf,
    pub data: PathBuf,
    pub data_anchor: DataAnchor,
}

impl PartialEq for CanonicalRoots {
    /// The anchor describes how the data root was reached, not which roots they are.
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source && self.data == other.data
    }
}

impl Eq for CanonicalRoots {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootError {
    InvalidSource,
    InvalidData,
    HomeRoot,
    Overlap,
    TooLong,
    /// The per-pass metadata budget ended before validation finished; resumable, not a conflict.
    LimitExceeded,
}

pub fn opencode_data_dir(
    explicit: Option<&OsStr>,
    xdg_data_home: Option<&OsStr>,
    home: &Path,
) -> PathBuf {
    if let Some(explicit) = explicit {
        return PathBuf::from(explicit);
    }
    if let Some(xdg) = xdg_data_home
        && !xdg.is_empty()
    {
        return PathBuf::from(xdg).join("opencode");
    }
    home.join(".local").join("share").join("opencode")
}

pub fn validate_roots<F: SourceFs>(
    fs: &F,
    source_root: &Path,
    data_dir: &Path,
    home: &Path,
    counters: &mut PassCounters,
) -> Result<CanonicalRoots, RootError> {
    if !source_root.is_absolute() || !home.is_absolute() {
        return Err(RootError::InvalidSource);
    }
    if !data_dir.is_absolute() {
        return Err(RootError::InvalidData);
    }
    if source_root.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES
        || data_dir.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES
    {
        return Err(RootError::TooLong);
    }

    let source = canonicalize_counted(fs, source_root, counters)
        .map_err(|error| root_error(&error, RootError::InvalidSource))?;
    if source.to_str().is_none() {
        return Err(RootError::InvalidSource);
    }
    let source_metadata = metadata_counted(fs, &source, counters)
        .map_err(|error| root_error(&error, RootError::InvalidSource))?;
    if !source_metadata.is_dir() {
        return Err(RootError::InvalidSource);
    }
    let canonical_home = canonicalize_counted(fs, home, counters)
        .map_err(|error| root_error(&error, RootError::InvalidSource))?;
    if source == Path::new("/") || source == canonical_home || canonical_home.starts_with(&source) {
        return Err(RootError::HomeRoot);
    }

    let (data, data_anchor) = canonicalize_future_dir(fs, data_dir, counters)
        .map_err(|error| root_error(&error, RootError::InvalidData))?;
    if data.to_str().is_none() {
        return Err(RootError::InvalidData);
    }
    if data.starts_with(&source) || source.starts_with(&data) {
        return Err(RootError::Overlap);
    }
    Ok(CanonicalRoots {
        source,
        data,
        data_anchor,
    })
}

fn root_error(error: &io::Error, otherwise: RootError) -> RootError {
    if crate::ingest::fs::budget_exhausted(error) {
        RootError::LimitExceeded
    } else {
        otherwise
    }
}

fn canonicalize_counted<F: SourceFs>(
    fs: &F,
    path: &Path,
    counters: &mut PassCounters,
) -> io::Result<PathBuf> {
    fs.canonicalize(path, counters)
}

fn metadata_counted<F: SourceFs>(
    fs: &F,
    path: &Path,
    counters: &mut PassCounters,
) -> io::Result<std::fs::Metadata> {
    fs.metadata(path, counters)
}

fn anchor_of(path: PathBuf, metadata: &std::fs::Metadata) -> DataAnchor {
    use std::os::unix::fs::MetadataExt;
    DataAnchor {
        path,
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

fn canonicalize_future_dir<F: SourceFs>(
    fs: &F,
    target: &Path,
    counters: &mut PassCounters,
) -> io::Result<(PathBuf, DataAnchor)> {
    match canonicalize_counted(fs, target, counters) {
        Ok(canonical) => {
            let metadata = metadata_counted(fs, &canonical, counters)?;
            if !metadata.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "data root is not a directory",
                ));
            }
            let anchor = anchor_of(canonical.clone(), &metadata);
            return Ok((canonical, anchor));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let mut suffix = Vec::new();
    let mut ancestor = target;
    loop {
        let name = ancestor.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "data root has no existing parent",
            )
        })?;
        suffix.push(name.to_os_string());
        ancestor = ancestor.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "data root has no existing parent",
            )
        })?;
        match canonicalize_counted(fs, ancestor, counters) {
            Ok(canonical) => {
                let metadata = metadata_counted(fs, &canonical, counters)?;
                if !metadata.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "data parent is not a directory",
                    ));
                }
                let anchor = anchor_of(canonical.clone(), &metadata);
                let mut resolved = canonical;
                for component in suffix.iter().rev() {
                    resolved.push(component);
                }
                return Ok((resolved, anchor));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
}

/// Resolves a data directory on the real filesystem for callers that hold no validated roots:
/// the nearest existing ancestor is canonicalized and its identity read once.
pub fn anchor_for(target: &Path) -> io::Result<(PathBuf, DataAnchor)> {
    let mut counters = PassCounters::default();
    canonicalize_future_dir(&crate::ingest::fs::RealSourceFs, target, &mut counters)
}
