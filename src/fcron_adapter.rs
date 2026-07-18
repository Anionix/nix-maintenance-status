//! Read-only normalization of fcron 3.4.0 and 3.4.1 source tables.
//!
//! The daemon's human-readable source is `<user>.orig` (or the explicitly
//! configured `systab.orig`).  fcron itself ignores dotted files at runtime;
//! this adapter therefore reports only configuration/schedule evidence and
//! never treats a source table as a loaded or executed job.

use std::ffi::CString;
use std::io::{self, Read};
use std::{fmt, path::Path, sync::Arc};

use thiserror::Error;

use crate::catalog::{
    AuthorityIdentityObservation, AuthorityResolution, AuthorityRole, AuthorityUnknownReason,
    ObservedAuthorityIdentity, PackageIdentityObservation, ProviderCatalog,
};
#[cfg(test)]
use crate::catalog::{CatalogScope, ObservedPackageIdentity};
use crate::evidence::{
    CaptureSequence, DefinitionOccurrence, DefinitionShape, InputError, ObservationComponent,
    ObservationUnknownReason, Presence, Provider, ProviderEvidence, ProviderEvidenceSet,
    ProviderLogicalKey, ShapeState, ShapeUnknownReason, SourceOccurrenceKey, SourceRoot,
    SourceRootId, Subject, UnavailableReason,
};
use crate::report::{
    FcronCalendarFields, FcronEntry, FcronEntryKind, FcronFieldAtom, FcronLoadAverage, FcronOption,
    FcronOptionSet, FcronPeriodicKeyword, FcronSchedule, FcronTimeField, FcronTimeValue,
    FcronTimezone, Schedule,
};

pub const MAX_FCRON_BYTES: usize = 64 * 1024;
pub const MAX_FCRON_LOGICAL_LINE: usize = 1024;
pub const MAX_FCRON_USER_ENTRIES: usize = 1024;
pub const MAX_FCRON_SYSTEM_ENTRIES: usize = 65_535;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FcronTableKind {
    UserSource,
    SystemSource,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FcronPathError {
    #[error("fcron spool root must be absolute")]
    NotAbsolute,
    #[error("fcron spool path contains an unsafe component")]
    UnsafeComponent,
    #[error("fcron spool root does not exist")]
    MissingRoot,
    #[error("fcron spool root is not a safe directory")]
    UnsafeRoot,
    #[error("fcron user identifier is invalid")]
    InvalidUser,
}

/// A caller-provided, existing `fcrontabs` root.  The root is intentionally
/// required before a production source path can be constructed: the adapter
/// never assumes the distro default and never discovers users or configuration.
#[derive(Clone)]
pub struct FcronSpoolRoot {
    dir: Arc<std::fs::File>,
}

impl fmt::Debug for FcronSpoolRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FcronSpoolRoot(<opaque>)")
    }
}

impl FcronSpoolRoot {
    #[cfg(unix)]
    pub fn new(path: &Path) -> Result<Self, FcronPathError> {
        if !path.is_absolute() {
            return Err(FcronPathError::NotAbsolute);
        }
        if path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        }) {
            return Err(FcronPathError::UnsafeComponent);
        }
        let metadata = std::fs::symlink_metadata(path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                FcronPathError::MissingRoot
            } else {
                FcronPathError::UnsafeRoot
            }
        })?;
        if !metadata.file_type().is_dir() || safe_parent_chain(path).is_none() {
            return Err(FcronPathError::UnsafeRoot);
        }
        use std::os::unix::fs::OpenOptionsExt;
        let dir = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| FcronPathError::UnsafeRoot)?;
        let opened = dir.metadata().map_err(|_| FcronPathError::UnsafeRoot)?;
        if !opened.is_dir() || !same_identity(&metadata, &opened) {
            return Err(FcronPathError::UnsafeRoot);
        }
        Ok(Self { dir: Arc::new(dir) })
    }

    pub fn user_source(&self, user: &str) -> Result<FcronSourcePath, FcronPathError> {
        validate_component(user)?;
        Ok(FcronSourcePath {
            root: Arc::clone(&self.dir),
            basename: format!("{user}.orig"),
            kind: FcronTableKind::UserSource,
        })
    }

    pub fn system_source(&self) -> FcronSourcePath {
        FcronSourcePath {
            root: Arc::clone(&self.dir),
            basename: String::from("systab.orig"),
            kind: FcronTableKind::SystemSource,
        }
    }
}

#[derive(Clone)]
pub struct FcronSourcePath {
    root: Arc<std::fs::File>,
    basename: String,
    kind: FcronTableKind,
}

impl fmt::Debug for FcronSourcePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FcronSourcePath")
            .field("kind", &self.kind)
            .finish()
    }
}

impl FcronSourcePath {
    pub const fn kind(&self) -> FcronTableKind {
        self.kind
    }
}

fn validate_component(value: &str) -> Result<(), FcronPathError> {
    if value.is_empty()
        || value.len() > 128
        || value == "."
        || value == ".."
        || value == "systab"
        || value.contains('/')
        || value.contains('\\')
        || value.chars().any(char::is_control)
    {
        return Err(FcronPathError::InvalidUser);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FcronFileStat {
    regular: bool,
    mode: u32,
    owner: u32,
    nlink: u64,
    dev: u64,
    ino: u64,
    size: u64,
    mtime: (i64, i64),
}

impl FcronFileStat {
    #[allow(clippy::too_many_arguments)]
    pub const fn fixture(
        regular: bool,
        mode: u32,
        owner: u32,
        nlink: u64,
        dev: u64,
        ino: u64,
        size: u64,
        mtime: (i64, i64),
    ) -> Self {
        Self {
            regular,
            mode,
            owner,
            nlink,
            dev,
            ino,
            size,
            mtime,
        }
    }

    fn same_generation(self, other: Self) -> bool {
        (self.dev, self.ino, self.size, self.mtime, self.nlink)
            == (other.dev, other.ino, other.size, other.mtime, other.nlink)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FcronTableResult {
    Absent,
    PresentEmpty,
    Present(FcronSchedule),
    Unknown(ObservationUnknownReason),
    Unavailable(UnavailableReason),
}

/// A source result branded with the fcron 3.4.1 parser contract. The brand
/// prevents evidence code from relabelling a 3.4.1 parse as 3.4.0 authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fcron341TableResult(FcronTableResult);

impl Fcron341TableResult {
    fn raw_state(&self) -> &FcronTableResult {
        &self.0
    }

    pub const fn presence(&self) -> Presence {
        self.0.presence()
    }
}

impl FcronTableResult {
    // LLM contract: this total projection preserves the five source states
    // one-for-one. Absent and PresentEmpty remain known structural facts;
    // Unknown and Unavailable retain their normalized reasons. No projection
    // upgrades failure to absence or performs I/O, parsing, inference, or
    // runtime scheduler observation.
    pub const fn presence(&self) -> Presence {
        match self {
            Self::Absent => Presence::Absent,
            Self::PresentEmpty => Presence::PresentEmpty,
            Self::Present(_) => Presence::Present,
            Self::Unknown(reason) => Presence::Unknown(*reason),
            Self::Unavailable(reason) => Presence::Unavailable(*reason),
        }
    }

    pub fn schedule(&self) -> Option<&FcronSchedule> {
        match self {
            Self::Present(schedule) => Some(schedule),
            _ => None,
        }
    }
}

/// Source-only normalization.  Unsupported source syntax is Unknown; no
/// scheduler runtime state is fabricated from `<user>.orig`.
// LLM contract: Present/PresentEmpty require one bounded, stable, regular
// source file whose generation and owner/mode are safe. Missing is Absent;
// malformed or unsupported grammar is Unknown; encoding, object, permission,
// size, and TOCTOU failures are Unavailable. This seam never executes a
// command, opens a socket, consults NSS, mutates files, or runs GC.
pub fn normalize_fcron_file(
    before: FcronFileStat,
    bytes: &[u8],
    after: FcronFileStat,
    kind: FcronTableKind,
    expected_owner: Option<u32>,
) -> FcronTableResult {
    normalize_fcron_file_with_contract(
        before,
        bytes,
        after,
        kind,
        expected_owner,
        FcronContractVersion::V3_4_0,
    )
}

fn normalize_fcron_file_with_contract(
    before: FcronFileStat,
    bytes: &[u8],
    after: FcronFileStat,
    kind: FcronTableKind,
    expected_owner: Option<u32>,
    contract: FcronContractVersion,
) -> FcronTableResult {
    if bytes.len() > MAX_FCRON_BYTES {
        return FcronTableResult::Unavailable(UnavailableReason::ResourceLimitExceeded);
    }
    let safe_mode = |stat: FcronFileStat| {
        let mode = stat.mode & 0o7777;
        stat.regular
            && stat.nlink == 1
            && mode & !0o640 == 0
            && mode & 0o400 != 0
            && expected_owner.is_none_or(|owner| stat.owner == owner)
    };
    if !before.same_generation(after) || before.size != bytes.len() as u64 {
        return FcronTableResult::Unavailable(UnavailableReason::ChangedDuringRead);
    }
    if !safe_mode(before) || !safe_mode(after) {
        return FcronTableResult::Unavailable(UnavailableReason::UnsafeObjectType);
    }
    let text = match std::str::from_utf8(bytes) {
        Ok(value) => value,
        Err(_) => return FcronTableResult::Unavailable(UnavailableReason::UnsupportedEncoding),
    };
    match parse_fcron_with_contract(text, kind, contract) {
        Ok(None) => FcronTableResult::PresentEmpty,
        Ok(Some(schedule)) => FcronTableResult::Present(schedule),
        Err(reason) => FcronTableResult::Unknown(reason),
    }
}

/// Normalize a fcron 3.4.1 source table. The versioned seam is explicit
/// because upstream changed command-tail acceptance; schedule fields remain
/// shared only after this policy-bound parser has validated the input.
// LLM contract: V3_4_1 maps one bounded byte observation to exactly one of
// PresentEmpty, Present, Unknown, or Unavailable. Absent is produced only by
// the read seam. It never upgrades a failure, retains command bytes, performs
// I/O, or infers runtime state.
pub fn normalize_fcron_3_4_1_file(
    before: FcronFileStat,
    bytes: &[u8],
    after: FcronFileStat,
    kind: FcronTableKind,
    expected_owner: Option<u32>,
) -> Fcron341TableResult {
    if kind != FcronTableKind::UserSource {
        return Fcron341TableResult(FcronTableResult::Unavailable(
            UnavailableReason::UnsafeObjectType,
        ));
    }
    Fcron341TableResult(normalize_fcron_file_with_contract(
        before,
        bytes,
        after,
        kind,
        expected_owner,
        FcronContractVersion::V3_4_1,
    ))
}

/// Read only an explicitly selected source table.  The caller must obtain the
/// spool root from local configuration/evidence; this function never assumes
/// `/var/spool/fcron`, enumerates users, follows links, or reads compiled
/// `new.*`/`rm.*` files.  A path ending in `.orig` is the sole accepted source
/// shape; `systab.orig` requires the explicit SystemSource kind.
#[cfg(unix)]
pub fn read_fcron_source(
    source: &FcronSourcePath,
    expected_owner: Option<u32>,
) -> FcronTableResult {
    read_fcron_file_inner(
        &source.root,
        &source.basename,
        source.kind,
        expected_owner,
        FcronContractVersion::V3_4_0,
    )
}

/// Read only a selected fcron 3.4.1 user source table. System `systab.orig`
/// is deliberately rejected until a version-specific authority and scope are
/// specified; no user enumeration or privilege transition is attempted.
// LLM contract: the selected user `.orig` path yields Absent, PresentEmpty,
// Present, Unknown, or Unavailable after one bounded read. System sources are
// always UnsafeObjectType; no state is upgraded, and no mutation, command,
// network, NSS, or privilege transition occurs.
#[cfg(unix)]
pub fn read_fcron_3_4_1_source(
    source: &FcronSourcePath,
    expected_owner: Option<u32>,
) -> Fcron341TableResult {
    if source.kind() != FcronTableKind::UserSource {
        return Fcron341TableResult(FcronTableResult::Unavailable(
            UnavailableReason::UnsafeObjectType,
        ));
    }
    Fcron341TableResult(read_fcron_file_inner(
        &source.root,
        &source.basename,
        source.kind,
        expected_owner,
        FcronContractVersion::V3_4_1,
    ))
}

#[cfg(unix)]
#[deprecated(note = "use FcronSpoolRoot::user_source/system_source and read_fcron_source")]
pub fn read_fcron_file(
    _path: &Path,
    _kind: FcronTableKind,
    _expected_owner: Option<u32>,
) -> FcronTableResult {
    // Arbitrary paths are fixture-only; production reads must carry an
    // anchored FcronSpoolRoot/FcronSourcePath pair.
    FcronTableResult::Unavailable(UnavailableReason::UnsafeObjectType)
}

#[cfg(unix)]
// LLM contract: this is the only production file-read transition. The
// validated root directory fd and basename are immutable inputs; openat with
// no-follow creates a stable leaf, and fstat-before/read/fstat-after accepts
// only one unchanged regular file on the root device. ENOENT is Absent;
// object, permission, resource, and TOCTOU failures are Unavailable; parsing
// then produces Present/PresentEmpty or Unknown. No pathname is re-resolved
// after the root is opened and no command, network, NSS, lock, or write runs.
fn read_fcron_file_inner(
    root: &Arc<std::fs::File>,
    basename: &str,
    kind: FcronTableKind,
    expected_owner: Option<u32>,
    contract: FcronContractVersion,
) -> FcronTableResult {
    let file = match open_fcron_leaf(root, basename) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return FcronTableResult::Absent,
        Err(error) => return FcronTableResult::Unavailable(io_reason(error)),
    };
    let before = match file.metadata() {
        Ok(metadata) => stat_from_metadata(&metadata),
        Err(error) => return FcronTableResult::Unavailable(io_reason(error)),
    };
    let root_stat = match root.metadata() {
        Ok(metadata) => stat_from_metadata(&metadata),
        Err(error) => return FcronTableResult::Unavailable(io_reason(error)),
    };
    if !before.regular || before.dev != root_stat.dev {
        return FcronTableResult::Unavailable(UnavailableReason::ChangedDuringRead);
    }
    if before.size > MAX_FCRON_BYTES as u64 {
        return FcronTableResult::Unavailable(UnavailableReason::ResourceLimitExceeded);
    }
    let mut bytes = Vec::with_capacity(before.size as usize);
    if let Err(error) = (&mut &file)
        .take((MAX_FCRON_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
    {
        return FcronTableResult::Unavailable(io_reason(error));
    }
    let after = match file.metadata() {
        Ok(metadata) => stat_from_metadata(&metadata),
        Err(error) => return FcronTableResult::Unavailable(io_reason(error)),
    };
    normalize_fcron_file_with_contract(before, &bytes, after, kind, expected_owner, contract)
}

#[cfg(unix)]
fn open_fcron_leaf(root: &Arc<std::fs::File>, basename: &str) -> io::Result<std::fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = CString::new(basename).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: root is an open directory fd retained by FcronSpoolRoot, name
    // is NUL-free and validated as one basename, and ownership transfers only
    // on a nonnegative descriptor.
    let fd = unsafe {
        libc::openat(
            root.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: fd is a fresh descriptor owned by this File.
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }
}

#[cfg(unix)]
fn safe_parent_chain(path: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    let mut current = path.parent()?;
    let mut root_device = None;
    loop {
        let metadata = std::fs::symlink_metadata(current).ok()?;
        if !metadata.file_type().is_dir() {
            return None;
        }
        if current != Path::new("/") {
            match root_device {
                Some(device) if device != metadata.dev() => return None,
                None => root_device = Some(metadata.dev()),
                _ => {}
            }
        }
        if current == Path::new("/") {
            return root_device;
        }
        current = current.parent()?;
    }
}

#[cfg(unix)]
fn same_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(unix)]
fn stat_from_metadata(metadata: &std::fs::Metadata) -> FcronFileStat {
    use std::os::unix::fs::MetadataExt;
    FcronFileStat::fixture(
        metadata.is_file(),
        metadata.mode(),
        metadata.uid(),
        metadata.nlink(),
        metadata.dev(),
        metadata.ino(),
        metadata.size(),
        (metadata.mtime(), metadata.mtime_nsec()),
    )
}

fn io_reason(error: io::Error) -> UnavailableReason {
    #[cfg(unix)]
    if error.raw_os_error() == Some(libc::ELOOP) {
        return UnavailableReason::UnsafeObjectType;
    }
    match error.kind() {
        io::ErrorKind::PermissionDenied => UnavailableReason::PermissionDenied,
        io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput => {
            UnavailableReason::MalformedEvidence
        }
        _ => UnavailableReason::OperationFailed,
    }
}

struct ParseContext {
    options: FcronOptionSet,
    timezone: Option<FcronTimezone>,
    entries: Vec<FcronEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FcronContractVersion {
    V3_4_0,
    V3_4_1,
}

#[cfg(test)]
fn parse_fcron(
    text: &str,
    kind: FcronTableKind,
) -> Result<Option<FcronSchedule>, ObservationUnknownReason> {
    parse_fcron_with_contract(text, kind, FcronContractVersion::V3_4_0)
}

fn parse_fcron_with_contract(
    text: &str,
    kind: FcronTableKind,
    contract: FcronContractVersion,
) -> Result<Option<FcronSchedule>, ObservationUnknownReason> {
    let mut context = ParseContext {
        options: FcronOptionSet::default(),
        timezone: None,
        entries: Vec::new(),
    };
    for line in logical_lines(text)? {
        parse_line(&line, &mut context, contract)?;
        let limit = match kind {
            FcronTableKind::UserSource => MAX_FCRON_USER_ENTRIES,
            FcronTableKind::SystemSource => MAX_FCRON_SYSTEM_ENTRIES,
        };
        if context.entries.len() > limit {
            return Err(ObservationUnknownReason::MalformedSyntax);
        }
    }
    if context.entries.is_empty() {
        return Ok(None);
    }
    FcronSchedule::new(context.entries, context.options, context.timezone)
        .map(Some)
        .map_err(|_| ObservationUnknownReason::MalformedSyntax)
}

fn logical_lines(text: &str) -> Result<Vec<String>, ObservationUnknownReason> {
    let mut lines = Vec::new();
    let mut logical = String::new();
    for segment in text.split_inclusive('\n') {
        let body = segment.strip_suffix('\n').unwrap_or(segment);
        if body.len() > MAX_FCRON_LOGICAL_LINE {
            return Err(ObservationUnknownReason::MalformedSyntax);
        }
        let continued = segment
            .ends_with('\n')
            .then(|| body.strip_suffix('\\'))
            .flatten();
        logical.push_str(continued.unwrap_or(body));
        if logical.len() > MAX_FCRON_LOGICAL_LINE {
            return Err(ObservationUnknownReason::MalformedSyntax);
        }
        if continued.is_some() {
            continue;
        }
        lines.push(std::mem::take(&mut logical));
    }
    if !logical.is_empty() {
        lines.push(logical);
    }
    Ok(lines)
}

fn parse_line(
    line: &str,
    context: &mut ParseContext,
    contract: FcronContractVersion,
) -> Result<(), ObservationUnknownReason> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(());
    }
    if let Some(rest) = line.strip_prefix('!') {
        let token = rest.trim();
        let (reset, token) = if token == "reset" {
            (true, "")
        } else if let Some(rest) = token.strip_prefix("reset,") {
            (true, rest)
        } else {
            (false, token)
        };
        if reset {
            context.options = FcronOptionSet::default();
            context.timezone = None;
        }
        if !token.is_empty() {
            let options = parse_options(token)?;
            context.options = context.options.merge(&options);
            update_timezone(context, &options);
        }
        return Ok(());
    }
    // A command is opaque to this adapter and may contain `=`. Dispatch
    // schedule-leading lines before considering environment assignments.
    match line.as_bytes().first().copied() {
        Some(b'@') => return parse_at_line(&line[1..], context, contract),
        Some(b'&') => return parse_calendar_line(&line[1..], context, true, contract),
        Some(b'%') => return parse_periodic_line(&line[1..], context, contract),
        Some(b'0'..=b'9') | Some(b'*') => {
            return parse_calendar_line(line, context, false, contract);
        }
        _ => {}
    }
    if let Some((name, value)) = line.split_once('=') {
        let name = name.trim();
        if !is_env_name(name) {
            return Err(ObservationUnknownReason::MalformedSyntax);
        }
        let _value = env_value(value)?;
        // USER/LOGNAME are intentionally not resolved through NSS. Other
        // assignments influence execution but are not schedule semantics.
        return Ok(());
    }
    Err(ObservationUnknownReason::UnsupportedSyntax)
}

fn parse_at_line(
    rest: &str,
    context: &mut ParseContext,
    contract: FcronContractVersion,
) -> Result<(), ObservationUnknownReason> {
    let rest = rest.trim_start();
    let mut fields = rest.splitn(2, char::is_whitespace);
    let head = fields.next().unwrap_or("");
    let tail = fields.next().unwrap_or("").trim_start();
    if head == "reboot" || head == "resume" {
        if tail.is_empty() {
            return Err(ObservationUnknownReason::MalformedSyntax);
        }
        validate_command_tail(tail, contract)?;
        context.entries.push(FcronEntry::new(
            FcronEntryKind::Reboot {
                resume: head == "resume",
            },
            context.options.clone(),
        ));
        return Ok(());
    }
    if let Some(keyword) = shortcut_keyword(head) {
        if tail.is_empty() {
            return Err(ObservationUnknownReason::MalformedSyntax);
        }
        validate_command_tail(tail, contract)?;
        let fields = shortcut_calendar_fields(keyword)?;
        let options = context.options.clone();
        ensure_context_options(&options, FcronEntryKind::Calendar(fields.clone()))?;
        context.entries.push(FcronEntry::new(
            FcronEntryKind::Calendar(fields),
            options.clone(),
        ));
        update_timezone(context, options.options());
        return Ok(());
    }
    let (options, frequency_token, command) = if head.is_empty() {
        let mut parts = rest.splitn(2, char::is_whitespace);
        let frequency = parts.next().unwrap_or("");
        (Vec::new(), frequency, parts.next().unwrap_or("").trim())
    } else if parse_time_value(head).is_ok() {
        // Official shorthand: `@5 1h command` means first(5), then a
        // one-hour cadence. Without the second duration, `@5 command` is
        // simply a five-minute cadence.
        let mut parts = tail.splitn(2, char::is_whitespace);
        let second = parts.next().unwrap_or("");
        let remainder = parts.next().unwrap_or("").trim_start();
        if parse_time_value(second).is_ok() && !remainder.is_empty() {
            (
                vec![FcronOption::First(parse_time_value(head)?)],
                second,
                remainder,
            )
        } else {
            (Vec::new(), head, tail)
        }
    } else {
        let options = parse_options(head)?;
        let mut parts = tail.splitn(2, char::is_whitespace);
        let frequency = parts.next().unwrap_or("");
        (options, frequency, parts.next().unwrap_or("").trim())
    };
    if command.is_empty() {
        return Err(ObservationUnknownReason::MalformedSyntax);
    }
    validate_command_tail(command, contract)?;
    let frequency = parse_time_value(frequency_token)?;
    if frequency.seconds() == 0 {
        return Err(ObservationUnknownReason::MalformedSyntax);
    }
    let options = context.options.merge(&options);
    context.entries.push(FcronEntry::new(
        FcronEntryKind::Elapsed { frequency },
        options.clone(),
    ));
    update_timezone(context, options.options());
    Ok(())
}

fn validate_command_tail(
    command: &str,
    contract: FcronContractVersion,
) -> Result<(), ObservationUnknownReason> {
    let command = command.trim_end();
    if command.is_empty() {
        return Err(ObservationUnknownReason::MalformedSyntax);
    }
    if matches!(contract, FcronContractVersion::V3_4_0)
        && let Some(quote) = command.as_bytes().first().copied()
        && (quote == b'\'' || quote == b'"')
    {
        if command.as_bytes().last().copied() != Some(quote) {
            return Err(ObservationUnknownReason::MalformedSyntax);
        }
        if command.len() < 2 || command[1..command.len() - 1].is_empty() {
            return Err(ObservationUnknownReason::MalformedSyntax);
        }
    }
    Ok(())
}

fn parse_calendar_line(
    rest: &str,
    context: &mut ParseContext,
    allow_frequency: bool,
    contract: FcronContractVersion,
) -> Result<(), ObservationUnknownReason> {
    // `&` accepts a glued numeric run-frequency (`&7 ...`); a separated
    // number is the first cron minute field (`& 0 5 * * * ...`).  Keeping
    // adjacency here preserves fcron's grammar without guessing from values.
    let glued_frequency = allow_frequency && !rest.starts_with(char::is_whitespace);
    let rest = rest.trim_start();
    let mut tokens = rest.split_whitespace();
    let first = tokens
        .next()
        .ok_or(ObservationUnknownReason::MalformedSyntax)?;
    let (local_options, frequency) = if glued_frequency && first.chars().all(|c| c.is_ascii_digit())
    {
        let value = first
            .parse::<u32>()
            .map_err(|_| ObservationUnknownReason::MalformedSyntax)?;
        if value < 2 {
            return Err(ObservationUnknownReason::UnsupportedSyntax);
        }
        (Vec::new(), Some(value))
    } else if glued_frequency
        && first != "*"
        && !first.starts_with("*/")
        && (first.contains(',') || first.contains('(') || is_option_name(first))
    {
        (parse_options(first)?, None)
    } else {
        (Vec::new(), None)
    };
    let mut field_tokens =
        if !allow_frequency || !glued_frequency || first == "*" || first.starts_with("*/") {
            vec![first]
        } else {
            Vec::new()
        };
    field_tokens.extend(tokens);
    let mut field_tokens = field_tokens.into_iter();
    let mut fields = Vec::new();
    for (index, (min, max, names)) in [
        (0, 59, false),
        (0, 23, false),
        (1, 31, false),
        (1, 12, true),
        (0, 7, true),
    ]
    .into_iter()
    .enumerate()
    {
        let token = field_tokens
            .next()
            .ok_or(ObservationUnknownReason::MalformedSyntax)?;
        fields.push(
            parse_field(token, min, max, names)
                .map_err(|_| ObservationUnknownReason::UnsupportedSyntax)?,
        );
        let _ = index;
    }
    let command = field_tokens.collect::<Vec<_>>().join(" ");
    if command.is_empty() {
        return Err(ObservationUnknownReason::MalformedSyntax);
    }
    validate_command_tail(&command, contract)?;
    let fields: [FcronTimeField; 5] = fields.try_into().expect("five calendar fields");
    let mut options = context.options.merge(&local_options);
    if let Some(frequency) = frequency {
        options = options.merge(&[FcronOption::RunFrequency(frequency)]);
    }
    ensure_context_options(
        &options,
        FcronEntryKind::Calendar(FcronCalendarFields::new(fields.clone())),
    )?;
    context.entries.push(FcronEntry::new(
        FcronEntryKind::Calendar(FcronCalendarFields::new(fields)),
        options.clone(),
    ));
    update_timezone(context, options.options());
    Ok(())
}

fn parse_periodic_line(
    rest: &str,
    context: &mut ParseContext,
    contract: FcronContractVersion,
) -> Result<(), ObservationUnknownReason> {
    let rest = rest.trim_start();
    let mut tokens = rest.split_whitespace();
    let head = tokens
        .next()
        .ok_or(ObservationUnknownReason::MalformedSyntax)?;
    let (keyword, local_options) = parse_periodic_head(head)?;
    let needed = match keyword {
        FcronPeriodicKeyword::Hourly | FcronPeriodicKeyword::Midhourly => 1,
        FcronPeriodicKeyword::Daily
        | FcronPeriodicKeyword::Middaily
        | FcronPeriodicKeyword::Nightly
        | FcronPeriodicKeyword::Weekly
        | FcronPeriodicKeyword::Midweekly => 2,
        FcronPeriodicKeyword::Monthly | FcronPeriodicKeyword::Midmonthly => 3,
        FcronPeriodicKeyword::Yearly | FcronPeriodicKeyword::Annually => 3,
        FcronPeriodicKeyword::Minutes
        | FcronPeriodicKeyword::Hours
        | FcronPeriodicKeyword::Days
        | FcronPeriodicKeyword::Months
        | FcronPeriodicKeyword::DayOfWeek => 5,
    };
    let remaining = tokens.collect::<Vec<_>>();
    let ranges = [
        (0, 59, false),
        (0, 23, false),
        (1, 31, false),
        (1, 12, true),
        (0, 7, true),
    ];
    // Short periodic forms use only the fields relevant to their keyword,
    // while the full five-field spelling is also official. Consume additional
    // leading field-shaped tokens when present, preserving their semantics.
    let mut field_count = needed;
    while field_count < ranges.len() {
        let Some(token) = remaining.get(field_count) else {
            break;
        };
        let (min, max, names) = ranges[field_count];
        if parse_field(token, min, max, names).is_err() {
            break;
        }
        field_count += 1;
    }
    if remaining.len() <= field_count {
        return Err(ObservationUnknownReason::MalformedSyntax);
    }
    validate_command_tail(&remaining[field_count..].join(" "), contract)?;
    let mut fields = Vec::new();
    for (index, (min, max, names)) in ranges.into_iter().enumerate() {
        if index < field_count {
            fields.push(
                parse_field(remaining[index], min, max, names)
                    .map_err(|_| ObservationUnknownReason::UnsupportedSyntax)?,
            );
        } else {
            fields.push(FcronTimeField::new(vec![FcronFieldAtom::Any]).expect("Any is nonempty"));
        }
    }
    let fields: [FcronTimeField; 5] = fields.try_into().expect("five calendar fields");
    // fcron resets the per-entry run-frequency while parsing a periodic line.
    // A run-frequency inherited from the file-wide context is therefore not
    // the same as a local `r(...)` option and must not invalidate the entry.
    if local_options
        .iter()
        .any(|option| matches!(option, FcronOption::RunFrequency(_)))
    {
        return Err(ObservationUnknownReason::UnsupportedSyntax);
    }
    let inherited = context
        .options
        .options()
        .iter()
        .filter(|option| !matches!(option, FcronOption::RunFrequency(_)))
        .cloned()
        .collect::<Vec<_>>();
    let options = FcronOptionSet::default()
        .merge(&inherited)
        .merge(&local_options);
    let full_range = fields
        .iter()
        .zip([(0, 59), (0, 23), (1, 31), (1, 12), (0, 7)])
        .all(|(field, (min, max))| field_is_full_range(field, min, max));
    if matches!(
        keyword,
        FcronPeriodicKeyword::Minutes
            | FcronPeriodicKeyword::Hours
            | FcronPeriodicKeyword::Days
            | FcronPeriodicKeyword::Months
            | FcronPeriodicKeyword::DayOfWeek
    ) && full_range
    {
        return Err(ObservationUnknownReason::UnsupportedSyntax);
    }
    ensure_context_options(
        &options,
        FcronEntryKind::Periodic {
            keyword,
            fields: Some(FcronCalendarFields::new(fields.clone())),
        },
    )?;
    context.entries.push(FcronEntry::new(
        FcronEntryKind::Periodic {
            keyword,
            fields: Some(FcronCalendarFields::new(fields)),
        },
        options.clone(),
    ));
    update_timezone(context, options.options());
    Ok(())
}

fn parse_periodic_head(
    value: &str,
) -> Result<(FcronPeriodicKeyword, Vec<FcronOption>), ObservationUnknownReason> {
    let tokens = option_tokens(value)?;
    let keyword = match tokens.first().copied().unwrap_or("") {
        "hourly" => FcronPeriodicKeyword::Hourly,
        "midhourly" => FcronPeriodicKeyword::Midhourly,
        "daily" => FcronPeriodicKeyword::Daily,
        "middaily" => FcronPeriodicKeyword::Middaily,
        "nightly" => FcronPeriodicKeyword::Nightly,
        "weekly" => FcronPeriodicKeyword::Weekly,
        "midweekly" => FcronPeriodicKeyword::Midweekly,
        "monthly" => FcronPeriodicKeyword::Monthly,
        "midmonthly" => FcronPeriodicKeyword::Midmonthly,
        "mins" => FcronPeriodicKeyword::Minutes,
        "hours" => FcronPeriodicKeyword::Hours,
        "days" => FcronPeriodicKeyword::Days,
        "mons" => FcronPeriodicKeyword::Months,
        "dow" => FcronPeriodicKeyword::DayOfWeek,
        _ => return Err(ObservationUnknownReason::UnsupportedSyntax),
    };
    let options = if tokens.len() == 1 {
        Vec::new()
    } else {
        parse_options(&tokens[1..].join(","))?
    };
    Ok((keyword, options))
}

fn shortcut_keyword(value: &str) -> Option<FcronPeriodicKeyword> {
    Some(match value {
        "hourly" => FcronPeriodicKeyword::Hourly,
        "daily" | "midnight" => FcronPeriodicKeyword::Daily,
        "weekly" => FcronPeriodicKeyword::Weekly,
        "monthly" => FcronPeriodicKeyword::Monthly,
        "yearly" => FcronPeriodicKeyword::Yearly,
        "annually" => FcronPeriodicKeyword::Annually,
        _ => return None,
    })
}

fn shortcut_calendar_fields(
    keyword: FcronPeriodicKeyword,
) -> Result<FcronCalendarFields, ObservationUnknownReason> {
    let any = || {
        FcronTimeField::new(vec![FcronFieldAtom::Any])
            .map_err(|_| ObservationUnknownReason::MalformedSyntax)
    };
    let value = |value| {
        FcronTimeField::new(vec![FcronFieldAtom::Value(value)])
            .map_err(|_| ObservationUnknownReason::MalformedSyntax)
    };
    let fields = match keyword {
        FcronPeriodicKeyword::Hourly => [value(0)?, any()?, any()?, any()?, any()?],
        FcronPeriodicKeyword::Daily => [value(0)?, value(0)?, any()?, any()?, any()?],
        FcronPeriodicKeyword::Weekly => [value(0)?, value(0)?, any()?, any()?, value(0)?],
        FcronPeriodicKeyword::Monthly => [value(0)?, value(0)?, value(1)?, any()?, any()?],
        FcronPeriodicKeyword::Yearly | FcronPeriodicKeyword::Annually => {
            [value(0)?, value(0)?, value(1)?, value(1)?, any()?]
        }
        _ => return Err(ObservationUnknownReason::UnsupportedSyntax),
    };
    Ok(FcronCalendarFields::new(fields))
}

fn parse_options(value: &str) -> Result<Vec<FcronOption>, ObservationUnknownReason> {
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        return Err(ObservationUnknownReason::MalformedSyntax);
    }
    let mut options = Vec::new();
    for token in option_tokens(value)? {
        let (name, argument) = match token.split_once('(') {
            Some((name, rest)) if rest.ends_with(')') => (name, Some(&rest[..rest.len() - 1])),
            Some(_) => return Err(ObservationUnknownReason::MalformedSyntax),
            None => (token, None),
        };
        let bool_value = |default| {
            argument.map_or(Ok(default), |arg| match arg {
                "true" | "yes" | "1" => Ok(true),
                "false" | "no" | "0" => Ok(false),
                _ => Err(ObservationUnknownReason::MalformedSyntax),
            })
        };
        let option = match name {
            "bootrun" | "b" => FcronOption::BootRun(bool_value(true)?),
            "dayand" => FcronOption::DayAnd(bool_value(true)?),
            "dayor" => FcronOption::DayOr(bool_value(true)?),
            "first" | "f" => FcronOption::First(parse_time_value(
                argument.ok_or(ObservationUnknownReason::MalformedSyntax)?,
            )?),
            "jitter" => FcronOption::Jitter(parse_u8(
                argument.ok_or(ObservationUnknownReason::MalformedSyntax)?,
                255,
            )?),
            "lavg" => FcronOption::Lavg(parse_lavg(
                argument.ok_or(ObservationUnknownReason::MalformedSyntax)?,
            )?),
            "lavg1" => FcronOption::LavgOne {
                slot: 1,
                value: parse_single_lavg(
                    argument.ok_or(ObservationUnknownReason::MalformedSyntax)?,
                )?,
            },
            "lavg5" => FcronOption::LavgOne {
                slot: 5,
                value: parse_single_lavg(
                    argument.ok_or(ObservationUnknownReason::MalformedSyntax)?,
                )?,
            },
            "lavg15" => FcronOption::LavgOne {
                slot: 15,
                value: parse_single_lavg(
                    argument.ok_or(ObservationUnknownReason::MalformedSyntax)?,
                )?,
            },
            "lavgand" => FcronOption::LavgAnd(bool_value(true)?),
            "lavgonce" => FcronOption::LavgOnce(bool_value(true)?),
            "lavgor" => FcronOption::LavgOr(bool_value(true)?),
            "random" => FcronOption::Random(bool_value(true)?),
            "runatreboot" => FcronOption::RunAtReboot(bool_value(true)?),
            "runatresume" => FcronOption::RunAtResume(bool_value(true)?),
            "runas" => {
                let arg = argument.ok_or(ObservationUnknownReason::MalformedSyntax)?;
                if arg.is_empty() || arg.len() > 128 || arg.chars().any(char::is_control) {
                    return Err(ObservationUnknownReason::MalformedSyntax);
                }
                FcronOption::RunAsOpaque
            }
            "runfreq" | "r" => {
                let value = parse_u32(
                    argument.ok_or(ObservationUnknownReason::MalformedSyntax)?,
                    65_535,
                )?;
                if value < 2 {
                    return Err(ObservationUnknownReason::UnsupportedSyntax);
                }
                FcronOption::RunFrequency(value)
            }
            "runonce" => FcronOption::RunOnce(bool_value(true)?),
            "serial" | "s" => FcronOption::Serial(bool_value(true)?),
            "serialonce" => FcronOption::SerialOnce(bool_value(true)?),
            "strict" => FcronOption::Strict(bool_value(true)?),
            "timezone" => {
                let arg = argument.ok_or(ObservationUnknownReason::MalformedSyntax)?;
                if arg.is_empty() {
                    FcronOption::TimezoneSystem
                } else if arg.len() > 128 || arg.chars().any(char::is_control) {
                    return Err(ObservationUnknownReason::MalformedSyntax);
                } else {
                    FcronOption::Timezone(FcronTimezone::new(arg.to_owned()))
                }
            }
            "until" | "u" => {
                let value =
                    parse_time_value(argument.ok_or(ObservationUnknownReason::MalformedSyntax)?)?;
                FcronOption::Until(value)
            }
            "volatile" => FcronOption::Volatile(bool_value(true)?),
            "erroronlymail" => FcronOption::ErrorOnlyMail(bool_value(true)?),
            "exesev" => FcronOption::ExeSev(bool_value(true)?),
            "forcemail" => FcronOption::ForceMail(bool_value(true)?),
            "mail" | "m" => FcronOption::Mail(bool_value(true)?),
            "mailfrom" => {
                let arg = argument.ok_or(ObservationUnknownReason::MalformedSyntax)?;
                if arg.len() > 256 || arg.chars().any(char::is_control) {
                    return Err(ObservationUnknownReason::MalformedSyntax);
                }
                FcronOption::MailFromOpaque
            }
            "mailto" => {
                let arg = argument.ok_or(ObservationUnknownReason::MalformedSyntax)?;
                if arg.len() > 256 || arg.chars().any(char::is_control) {
                    return Err(ObservationUnknownReason::MalformedSyntax);
                }
                FcronOption::MailToOpaque
            }
            "nice" | "n" => {
                let arg = argument.ok_or(ObservationUnknownReason::MalformedSyntax)?;
                let value = arg
                    .parse::<i16>()
                    .map_err(|_| ObservationUnknownReason::MalformedSyntax)?;
                if !(-20..=19).contains(&value) {
                    return Err(ObservationUnknownReason::MalformedSyntax);
                }
                FcronOption::Nice(value as i8)
            }
            "nolog" => FcronOption::NoLog(bool_value(true)?),
            "noticenotrun" => FcronOption::NoticeNotRun(bool_value(true)?),
            "rebootreset" => FcronOption::RebootReset(bool_value(true)?),
            "stdout" => FcronOption::Stdout(bool_value(true)?),
            "tzdiff" => {
                let arg = argument.ok_or(ObservationUnknownReason::MalformedSyntax)?;
                let value = arg
                    .parse::<i16>()
                    .map_err(|_| ObservationUnknownReason::MalformedSyntax)?;
                if !(-24..=24).contains(&value) {
                    return Err(ObservationUnknownReason::MalformedSyntax);
                }
                FcronOption::TzDiff(value)
            }
            "reset" => return Err(ObservationUnknownReason::UnsupportedSyntax),
            _ => return Err(ObservationUnknownReason::UnsupportedSyntax),
        };
        if argument.is_some()
            && matches!(
                option,
                FcronOption::BootRun(_)
                    | FcronOption::DayAnd(_)
                    | FcronOption::DayOr(_)
                    | FcronOption::Random(_)
                    | FcronOption::RunAtReboot(_)
                    | FcronOption::RunAtResume(_)
                    | FcronOption::Serial(_)
                    | FcronOption::SerialOnce(_)
                    | FcronOption::Strict(_)
                    | FcronOption::Volatile(_)
            )
            && token.contains('(')
        {
            // bool arguments are valid; this branch is intentionally a no-op.
        }
        options.push(option);
    }
    Ok(options)
}

fn option_tokens(value: &str) -> Result<Vec<&str>, ObservationUnknownReason> {
    let mut tokens = Vec::new();
    let mut start = 0;
    let mut depth = 0u8;
    for (index, byte) in value.bytes().enumerate() {
        match byte {
            b'(' => {
                depth = depth
                    .checked_add(1)
                    .ok_or(ObservationUnknownReason::MalformedSyntax)?
            }
            b')' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or(ObservationUnknownReason::MalformedSyntax)?
            }
            b',' if depth == 0 => {
                if index == start {
                    return Err(ObservationUnknownReason::MalformedSyntax);
                }
                tokens.push(&value[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    if depth != 0 || start == value.len() {
        return Err(ObservationUnknownReason::MalformedSyntax);
    }
    tokens.push(&value[start..]);
    Ok(tokens)
}

fn ensure_context_options(
    options: &FcronOptionSet,
    kind: FcronEntryKind,
) -> Result<(), ObservationUnknownReason> {
    // LLM contract: a parsed entry is either accepted with options valid for
    // its kind or becomes UnsupportedSyntax; no option is silently dropped.
    // Calendar entries reject Random, periodic entries reject Jitter, while
    // local periodic RunFrequency is rejected at the line parser. Inherited
    // RunFrequency remains valid because fcron resets it for periodic lines.
    if matches!(kind, FcronEntryKind::Calendar(_))
        && options
            .options()
            .iter()
            .any(|option| matches!(option, FcronOption::Random(_)))
    {
        return Err(ObservationUnknownReason::UnsupportedSyntax);
    }
    if matches!(kind, FcronEntryKind::Periodic { .. })
        && options
            .options()
            .iter()
            .any(|option| matches!(option, FcronOption::Jitter(_)))
    {
        return Err(ObservationUnknownReason::UnsupportedSyntax);
    }
    Ok(())
}

fn update_timezone(context: &mut ParseContext, options: &[FcronOption]) {
    if let Some(option) = options.iter().rev().find(|option| {
        matches!(
            option,
            FcronOption::Timezone(_) | FcronOption::TimezoneSystem
        )
    }) {
        context.timezone = match option {
            FcronOption::Timezone(value) => Some(value.clone()),
            FcronOption::TimezoneSystem => None,
            _ => unreachable!(),
        };
    }
}

fn entry_timezone(entry: &FcronEntry) -> Option<FcronTimezone> {
    entry
        .options()
        .options()
        .iter()
        .find_map(|option| match option {
            FcronOption::Timezone(value) => Some(value.clone()),
            FcronOption::TimezoneSystem => None,
            _ => None,
        })
}

fn env_value(value: &str) -> Result<&str, ObservationUnknownReason> {
    let value = value.trim_end();
    if value.bytes().any(|byte| byte < 0x20 && byte != b'\t') {
        return Err(ObservationUnknownReason::MalformedSyntax);
    }
    if let Some(quote) = value
        .as_bytes()
        .first()
        .copied()
        .filter(|v| matches!(v, b'\'' | b'"'))
    {
        if value.len() < 2 || value.as_bytes().last() != Some(&quote) {
            return Err(ObservationUnknownReason::MalformedSyntax);
        }
        return Ok(&value[1..value.len() - 1]);
    }
    if value.ends_with(['\'', '"']) {
        return Err(ObservationUnknownReason::MalformedSyntax);
    }
    Ok(value.trim())
}

fn is_env_name(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(c) if c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn is_option_name(value: &str) -> bool {
    value
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic())
}

fn parse_time_value(value: &str) -> Result<FcronTimeValue, ObservationUnknownReason> {
    if value.is_empty() || value.len() > 64 {
        return Err(ObservationUnknownReason::MalformedSyntax);
    }
    let mut total = 0u64;
    let mut digits = String::new();
    for character in value.chars() {
        if character.is_ascii_digit() {
            digits.push(character);
            continue;
        }
        let number = digits
            .parse::<u64>()
            .map_err(|_| ObservationUnknownReason::MalformedSyntax)?;
        digits.clear();
        let multiplier = match character {
            'm' => 4 * 7 * 24 * 60 * 60,
            'w' => 7 * 24 * 60 * 60,
            'd' => 24 * 60 * 60,
            'h' => 60 * 60,
            's' => 1,
            _ => return Err(ObservationUnknownReason::UnsupportedSyntax),
        };
        total = total
            .checked_add(
                number
                    .checked_mul(multiplier)
                    .ok_or(ObservationUnknownReason::MalformedSyntax)?,
            )
            .ok_or(ObservationUnknownReason::MalformedSyntax)?;
    }
    if !digits.is_empty() {
        total = total
            .checked_add(
                digits
                    .parse::<u64>()
                    .map_err(|_| ObservationUnknownReason::MalformedSyntax)?
                    .checked_mul(60)
                    .ok_or(ObservationUnknownReason::MalformedSyntax)?,
            )
            .ok_or(ObservationUnknownReason::MalformedSyntax)?;
    }
    (total <= 31_536_000_000)
        .then_some(FcronTimeValue::from_seconds(total))
        .ok_or(ObservationUnknownReason::MalformedSyntax)
}

fn parse_u8(value: &str, max: u8) -> Result<u8, ObservationUnknownReason> {
    let parsed = value
        .parse::<u16>()
        .map_err(|_| ObservationUnknownReason::MalformedSyntax)?;
    (parsed <= max as u16)
        .then_some(parsed as u8)
        .ok_or(ObservationUnknownReason::MalformedSyntax)
}

fn parse_u32(value: &str, max: u32) -> Result<u32, ObservationUnknownReason> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| ObservationUnknownReason::MalformedSyntax)?;
    (parsed <= max as u64)
        .then_some(parsed as u32)
        .ok_or(ObservationUnknownReason::MalformedSyntax)
}

fn parse_lavg(value: &str) -> Result<[Option<FcronLoadAverage>; 3], ObservationUnknownReason> {
    let mut values = [None; 3];
    let parts = value.split(',').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(ObservationUnknownReason::MalformedSyntax);
    }
    for (index, part) in parts.into_iter().enumerate() {
        values[index] = Some(parse_single_lavg(part)?);
    }
    Ok(values)
}

fn parse_single_lavg(value: &str) -> Result<FcronLoadAverage, ObservationUnknownReason> {
    if value.is_empty() || value.len() > 32 || value.chars().any(char::is_control) {
        return Err(ObservationUnknownReason::MalformedSyntax);
    }
    let has_decimal = value.contains('.');
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if fraction.contains('.') || whole.contains(|c: char| !c.is_ascii_digit()) {
        return Err(ObservationUnknownReason::MalformedSyntax);
    }
    let whole = if whole.is_empty() { "0" } else { whole }
        .parse::<u16>()
        .map_err(|_| ObservationUnknownReason::MalformedSyntax)?;
    if (has_decimal && fraction.is_empty()) || fraction.chars().any(|c| !c.is_ascii_digit()) {
        return Err(ObservationUnknownReason::MalformedSyntax);
    }
    let mut tenths = whole
        .checked_mul(10)
        .ok_or(ObservationUnknownReason::MalformedSyntax)?;
    if let Some(first) = fraction.as_bytes().first() {
        tenths = tenths
            .checked_add(u16::from(first - b'0'))
            .ok_or(ObservationUnknownReason::MalformedSyntax)?;
        if fraction
            .as_bytes()
            .get(1)
            .is_some_and(|digit| *digit >= b'5')
        {
            tenths = tenths
                .checked_add(1)
                .ok_or(ObservationUnknownReason::MalformedSyntax)?;
        }
    }
    if tenths > 2_550 {
        return Err(ObservationUnknownReason::MalformedSyntax);
    }
    Ok(FcronLoadAverage::from_tenths(tenths))
}

fn parse_field(value: &str, min: u8, max: u8, names: bool) -> Result<FcronTimeField, ()> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(());
    }
    let mut atoms = Vec::new();
    for item in value.split(',') {
        let mut parts = item.split('~');
        let base = parts.next().ok_or(())?;
        let excluded = parts
            .map(|part| parse_value(part, min, max, names))
            .collect::<Result<Vec<_>, _>>()?;
        if excluded.len() > 32 {
            return Err(());
        }
        let (base, step) = base.split_once('/').map_or((base, 1), |(base, step)| {
            (base, step.parse::<u8>().unwrap_or(0))
        });
        if step == 0 {
            return Err(());
        }
        if base == "*" {
            if excluded.is_empty() && step == 1 {
                atoms.push(FcronFieldAtom::Any);
            } else {
                atoms.push(FcronFieldAtom::Range {
                    start: min,
                    end: max,
                    step,
                    excluded,
                });
            }
            continue;
        }
        let (start, end) = if let Some((start, end)) = base.split_once('-') {
            let start = parse_value(start, min, max, names)?;
            let end = parse_value(end, min, max, names)?;
            if start > end {
                return Err(());
            }
            (start, end)
        } else {
            let value = parse_value(base, min, max, names)?;
            (value, value)
        };
        if start == end && step != 1 {
            return Err(());
        }
        let named = if start == end {
            parse_named_value(base, min, max, names)
        } else {
            None
        };
        atoms.push(match named {
            Some(value) if excluded.is_empty() && step == 1 => FcronFieldAtom::Name(value),
            None if start == end && excluded.is_empty() => FcronFieldAtom::Value(start),
            None => FcronFieldAtom::Range {
                start,
                end,
                step,
                excluded,
            },
            Some(_) => FcronFieldAtom::Range {
                start,
                end,
                step,
                excluded,
            },
        });
    }
    FcronTimeField::new(atoms).map_err(|_| ())
}

fn parse_value(value: &str, min: u8, max: u8, names: bool) -> Result<u8, ()> {
    if let Some(value) = parse_named_value(value, min, max, names) {
        return Ok(value);
    }
    let value = value.parse::<u8>().map_err(|_| ())?;
    (min..=max).contains(&value).then_some(value).ok_or(())
}

fn parse_named_value(value: &str, min: u8, max: u8, names: bool) -> Option<u8> {
    if !names || value.len() != 3 {
        return None;
    }
    let upper = value.to_ascii_uppercase();
    if max == 12 {
        return [
            "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC",
        ]
        .iter()
        .position(|name| *name == upper)
        .map(|index| index as u8 + 1)
        .filter(|value| (min..=max).contains(value));
    }
    if max == 7 {
        return ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"]
            .iter()
            .position(|name| *name == upper)
            .map(|index| index as u8)
            .filter(|value| (min..=max).contains(value));
    }
    None
}

fn field_is_full_range(field: &FcronTimeField, min: u8, max: u8) -> bool {
    match field.atoms() {
        [FcronFieldAtom::Any] => true,
        [
            FcronFieldAtom::Range {
                start,
                end,
                step,
                excluded,
            },
        ] => *start == min && *end == max && *step == 1 && excluded.is_empty(),
        _ => false,
    }
}

/// Build the exact fcron 3.4.0 scheduler ContractPin used by the embedded
/// catalog.  A caller still supplies the observed package identity to the
/// resolver; this helper only prevents callers from inventing a weaker pin.
pub fn fcron_3_4_0_contract_observation() -> AuthorityIdentityObservation {
    let identity = ObservedAuthorityIdentity::contract_with_fingerprint(
        "yo8192/fcron",
        "8198d4b90690fb0f53cca931b6e9bb6d4b9e6f83",
        "doc/en/fcrontab.5.sgml",
        Some("3.4.0"),
        None,
        Some("fcron-3.4.0-v1"),
    );
    match identity {
        Ok(identity) => AuthorityIdentityObservation::Known(identity),
        Err(_) => AuthorityIdentityObservation::Malformed,
    }
}

/// Build the exact fcron 3.4.1 ContractPin. It is intentionally independent
/// from 3.4.0 even though the normalized schedule projection is shared after
/// the version-specific parser policy has run.
pub fn fcron_3_4_1_contract_observation() -> AuthorityIdentityObservation {
    let identity = ObservedAuthorityIdentity::contract_with_fingerprint(
        "yo8192/fcron",
        "a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130",
        "doc/en/fcrontab.5.sgml",
        Some("3.4.1"),
        None,
        Some("fcron-3.4.1-v1"),
    );
    match identity {
        Ok(identity) => AuthorityIdentityObservation::Known(identity),
        Err(_) => AuthorityIdentityObservation::Malformed,
    }
}

/// Resolve scheduler semantics only when both version/package evidence and the
/// exact ContractPin are observed. Unknown or mismatched inputs remain
/// Unresolved; this function never treats a hard-coded revision as observed.
pub fn resolve_fcron_3_4_0_authority(
    package: &PackageIdentityObservation,
    contract: &AuthorityIdentityObservation,
) -> AuthorityResolution {
    ProviderCatalog::embedded().resolve_cron_scheduler_semantics(Provider::Fcron, package, contract)
}

/// Resolve 3.4.1 only from the exact package observation and versioned
/// ContractPin. No 3.4.0 authority is borrowed when the package is unknown.
pub fn resolve_fcron_3_4_1_authority(
    package: &PackageIdentityObservation,
    contract: &AuthorityIdentityObservation,
) -> AuthorityResolution {
    let expected_contract = fcron_3_4_1_contract_observation();
    if contract != &expected_contract {
        return AuthorityResolution::Unresolved(match contract {
            AuthorityIdentityObservation::Unavailable => {
                AuthorityUnknownReason::IdentityUnavailable
            }
            AuthorityIdentityObservation::Malformed => AuthorityUnknownReason::IdentityMalformed,
            AuthorityIdentityObservation::Known(_) => {
                AuthorityUnknownReason::ExactBasisUnverifiable
            }
        });
    }
    ProviderCatalog::embedded().resolve_cron_scheduler_semantics(Provider::Fcron, package, contract)
}

/// Convert source-only fcron configuration into report evidence. Runtime,
/// Activity, Runs, and LastResult remain Unknown because the daemon ignores
/// `.orig` files and the adapter never reads compiled state or logs.
// LLM contract: only a Present schedule receives a source occurrence and can
// become an inventory candidate. Absent, PresentEmpty, Unknown, and Unavailable
// retain a valid source occurrence as an evidence discriminator but remain
// evidence-only; runtime-like claims are always Unknown. Exact package and
// ContractPin observations may resolve SchedulerSemantics, while missing or
// mismatched authority remains Unresolved. This transition is pure and does
// no I/O, NSS, network, telemetry, mutation, elevation, or GC execution.
pub fn fcron_evidence_for_table(
    result: &FcronTableResult,
    subject: Subject,
    source_id: SourceRootId,
    ordinal: u32,
    capture: u32,
) -> Result<Vec<ProviderEvidence>, InputError> {
    fcron_evidence_for_table_with_authority(
        result,
        subject,
        source_id,
        ordinal,
        capture,
        &PackageIdentityObservation::Unavailable,
        &AuthorityIdentityObservation::Unavailable,
    )
}

/// Variant for a caller that has independently probed the package and exact
/// scheduler contract. Source-only evidence remains useful without it, but
/// only this seam can produce a Resolved SchedulerSemantics authority.
pub fn fcron_evidence_for_table_with_authority(
    result: &FcronTableResult,
    subject: Subject,
    source_id: SourceRootId,
    ordinal: u32,
    capture: u32,
    package: &PackageIdentityObservation,
    contract: &AuthorityIdentityObservation,
) -> Result<Vec<ProviderEvidence>, InputError> {
    let scheduler_authority = resolve_fcron_3_4_0_authority(package, contract);
    fcron_evidence_for_table_with_resolved_authority(
        result,
        subject,
        source_id,
        ordinal,
        capture,
        scheduler_authority,
    )
}

fn fcron_evidence_for_table_with_resolved_authority(
    result: &FcronTableResult,
    subject: Subject,
    source_id: SourceRootId,
    ordinal: u32,
    capture: u32,
    scheduler_authority: AuthorityResolution,
) -> Result<Vec<ProviderEvidence>, InputError> {
    let source_key_available = source_id != SourceRootId::new(0) && ordinal != 0;
    let evidence_presence = if source_key_available {
        result.presence()
    } else {
        Presence::Unavailable(UnavailableReason::MalformedEvidence)
    };
    let source_occurrence = source_key_available.then(|| {
        DefinitionOccurrence::new(
            ProviderLogicalKey::Anonymous,
            SourceOccurrenceKey::new(SourceRoot::FcronTable(source_id), ordinal),
            CaptureSequence::new(capture),
        )
    });
    let evidence_only_rows = |presence: Presence, occurrence: Option<&DefinitionOccurrence>| {
        let mut rows = Vec::new();
        for component in [
            ObservationComponent::Configuration,
            ObservationComponent::Schedule,
        ] {
            let mut row = match occurrence {
                Some(occurrence) => ProviderEvidence::with_occurrence(
                    Provider::Fcron,
                    subject,
                    component,
                    presence,
                    occurrence.clone(),
                )?,
                None => ProviderEvidence::new(Provider::Fcron, subject, component, presence)?,
            };
            if component == ObservationComponent::Schedule {
                row = row.with_authority(AuthorityRole::SchedulerSemantics, scheduler_authority)?;
            }
            rows.push(row);
        }
        for component in [
            ObservationComponent::Runtime,
            ObservationComponent::Activity,
            ObservationComponent::Runs,
            ObservationComponent::LastResult,
        ] {
            let runtime_presence = Presence::Unknown(ObservationUnknownReason::UnsupportedSyntax);
            rows.push(match occurrence {
                Some(occurrence) => ProviderEvidence::with_occurrence(
                    Provider::Fcron,
                    subject,
                    component,
                    runtime_presence,
                    occurrence.clone(),
                )?,
                None => {
                    ProviderEvidence::new(Provider::Fcron, subject, component, runtime_presence)?
                }
            });
        }
        Ok(rows)
    };
    let Some(schedule) = result.schedule().filter(|_| source_key_available) else {
        // LLM contract: non-Present source states are evidence-only. They do
        // not create an invented definition; Unknown/Unavailable reasons are
        // retained and a missing source key never becomes an inferred one.
        return evidence_only_rows(evidence_presence, source_occurrence.as_ref());
    };

    let last_index = schedule.entries().len().checked_sub(1);
    let ordinal_fits = last_index
        .and_then(|last| u32::try_from(last).ok())
        .and_then(|last| ordinal.checked_add(last))
        .is_some();
    if !ordinal_fits {
        // A source-local key that cannot be represented deterministically is
        // unavailable, not a parser error. Drop the occurrence discriminator
        // so no malformed candidate can enter the inventory.
        return evidence_only_rows(
            Presence::Unavailable(UnavailableReason::MalformedEvidence),
            None,
        );
    }

    // LLM contract: a Present table transitions to one occurrence per
    // normalized entry, with a deterministic source-local ordinal. Capture
    // remains occurrence evidence; the later inventory seam decides whether
    // to exclude it from logical identity. Command bytes and I/O never enter
    // identity or output.
    let mut rows = Vec::with_capacity(schedule.entries().len() * 7);
    for (index, entry) in schedule.entries().iter().enumerate() {
        let entry_schedule = FcronSchedule::new(
            vec![entry.clone()],
            entry.options().clone(),
            entry_timezone(entry),
        )
        .map_err(|_| InputError::InvalidNormalizedValue)?;
        let occurrence = DefinitionOccurrence::new(
            ProviderLogicalKey::Anonymous,
            SourceOccurrenceKey::new(
                SourceRoot::FcronTable(source_id),
                ordinal
                    .checked_add(index as u32)
                    .ok_or(InputError::InvalidNormalizedValue)?,
            ),
            CaptureSequence::new(capture),
        )
        .with_shape(DefinitionShape::Fcron {
            schedule: ShapeState::Known(entry_schedule.clone()),
            command: ShapeState::Unknown(ShapeUnknownReason::NotObserved),
            context: ShapeState::Unknown(ShapeUnknownReason::NotObserved),
        })?;
        for component in [
            ObservationComponent::Configuration,
            ObservationComponent::Schedule,
        ] {
            let mut row = ProviderEvidence::with_occurrence(
                Provider::Fcron,
                subject,
                component,
                Presence::Present,
                occurrence.clone(),
            )?;
            if component == ObservationComponent::Schedule {
                row = row.with_schedule(Schedule::Fcron(entry_schedule.clone()))?;
                row = row.with_authority(AuthorityRole::SchedulerSemantics, scheduler_authority)?;
            }
            rows.push(row);
        }
        rows.push(ProviderEvidence::with_occurrence(
            Provider::Fcron,
            subject,
            ObservationComponent::Command,
            Presence::Unknown(ObservationUnknownReason::UnsupportedSyntax),
            occurrence.clone(),
        )?);
        for component in [
            ObservationComponent::Runtime,
            ObservationComponent::Activity,
            ObservationComponent::Runs,
            ObservationComponent::LastResult,
        ] {
            rows.push(ProviderEvidence::with_occurrence(
                Provider::Fcron,
                subject,
                component,
                Presence::Unknown(ObservationUnknownReason::UnsupportedSyntax),
                occurrence.clone(),
            )?);
        }
    }
    Ok(rows)
}

pub fn fcron_3_4_1_evidence_for_table(
    result: &Fcron341TableResult,
    subject: Subject,
    source_id: SourceRootId,
    ordinal: u32,
    capture: u32,
) -> Result<Vec<ProviderEvidence>, InputError> {
    fcron_3_4_1_evidence_for_table_with_authority(
        result,
        subject,
        source_id,
        ordinal,
        capture,
        &PackageIdentityObservation::Unavailable,
        &AuthorityIdentityObservation::Unavailable,
    )
}

// LLM contract: only the private-branded V3_4_1 result can enter this seam.
// Authority is Resolved only when exact package and ContractPin evidence both
// match; otherwise it remains Unresolved. Source rows preserve configuration
// presence, keep runtime-like claims Unknown, leave AutomationMapping
// NotClaimed, and never retain commands or perform I/O.
pub fn fcron_3_4_1_evidence_for_table_with_authority(
    result: &Fcron341TableResult,
    subject: Subject,
    source_id: SourceRootId,
    ordinal: u32,
    capture: u32,
    package: &PackageIdentityObservation,
    contract: &AuthorityIdentityObservation,
) -> Result<Vec<ProviderEvidence>, InputError> {
    let scheduler_authority = resolve_fcron_3_4_1_authority(package, contract);
    fcron_evidence_for_table_with_resolved_authority(
        result.raw_state(),
        subject,
        source_id,
        ordinal,
        capture,
        scheduler_authority,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FcronNormalizedObservation {
    table_state: FcronTableResult,
    evidence: ProviderEvidenceSet,
}

impl FcronNormalizedObservation {
    pub const fn table_state(&self) -> &FcronTableResult {
        &self.table_state
    }

    pub const fn evidence(&self) -> &ProviderEvidenceSet {
        &self.evidence
    }
}

pub fn normalize_fcron_snapshot(
    result: FcronTableResult,
    subject: Subject,
    source_id: SourceRootId,
    ordinal: u32,
    capture: u32,
) -> Result<FcronNormalizedObservation, InputError> {
    Ok(FcronNormalizedObservation {
        evidence: ProviderEvidenceSet::new(fcron_evidence_for_table(
            &result, subject, source_id, ordinal, capture,
        )?)?,
        table_state: result,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat(size: usize) -> FcronFileStat {
        FcronFileStat::fixture(true, 0o600, 1000, 1, 1, 2, size as u64, (3, 4))
    }

    #[test]
    fn parses_all_fcron_entry_families_without_commands() {
        let text = b"TZ='Europe/Tokyo'\n!serial\n@ 2h30 /bin/true\n&bootrun 5 1 * * MON /bin/true\n%nightly,random * 21-23 /bin/true\n";
        let result = normalize_fcron_file(
            stat(text.len()),
            text,
            stat(text.len()),
            FcronTableKind::UserSource,
            Some(1000),
        );
        let FcronTableResult::Present(schedule) = result else {
            panic!()
        };
        assert_eq!(schedule.entries().len(), 3);
        assert_eq!(
            schedule.entries()[0].kind(),
            &FcronEntryKind::Elapsed {
                frequency: FcronTimeValue::from_seconds(9000)
            }
        );
        assert!(
            schedule
                .entries()
                .iter()
                .any(|entry| !entry.options().options().is_empty())
        );
    }

    #[test]
    fn present_table_keeps_one_occurrence_per_entry() {
        let text = b"@daily /bin/true\n@daily /bin/true\n";
        let result = normalize_fcron_file(
            stat(text.len()),
            text,
            stat(text.len()),
            FcronTableKind::UserSource,
            Some(1000),
        );
        let rows =
            fcron_evidence_for_table(&result, Subject::uid(1000), SourceRootId::new(9), 99, 4)
                .unwrap();
        let mut occurrences: Vec<_> = rows
            .iter()
            .filter_map(|row| row.occurrence())
            .cloned()
            .collect();
        occurrences.sort();
        occurrences.dedup();
        assert_eq!(occurrences.len(), 2);
        assert_eq!(
            occurrences
                .iter()
                .map(|occurrence| occurrence.source().ordinal())
                .collect::<Vec<_>>(),
            vec![99, 100]
        );
        assert_eq!(rows.len(), 14);
        assert!(format!("{rows:?}").contains("<opaque>"));
        let contextual_text = b"@daily /bin/true\n!timezone(Europe/Tokyo)\n@daily /bin/true\n";
        let contextual = normalize_fcron_file(
            stat(contextual_text.len()),
            contextual_text,
            stat(contextual_text.len()),
            FcronTableKind::UserSource,
            Some(1000),
        );
        let contextual_rows =
            fcron_evidence_for_table(&contextual, Subject::uid(1000), SourceRootId::new(10), 1, 4)
                .unwrap();
        let schedules: Vec<_> = contextual_rows
            .iter()
            .filter_map(|row| match row.schedule() {
                Some(Schedule::Fcron(schedule)) => Some(schedule),
                _ => None,
            })
            .collect();
        assert_eq!(schedules.len(), 2);
        assert!(schedules[0].timezone().is_none());
        assert!(schedules[1].timezone().is_some());
        let inherited_run_frequency = b"!runfreq(7)\n%daily * 5 /bin/true\n";
        let inherited = normalize_fcron_file(
            stat(inherited_run_frequency.len()),
            inherited_run_frequency,
            stat(inherited_run_frequency.len()),
            FcronTableKind::UserSource,
            Some(1000),
        );
        let inherited_rows =
            fcron_evidence_for_table(&inherited, Subject::uid(1000), SourceRootId::new(11), 1, 4)
                .unwrap();
        let inherited_schedule = inherited_rows.iter().find_map(|row| match row.schedule() {
            Some(Schedule::Fcron(schedule)) => Some(schedule),
            _ => None,
        });
        assert!(inherited_schedule.is_some_and(|schedule| {
            schedule.entries()[0]
                .options()
                .options()
                .iter()
                .all(|option| !matches!(option, FcronOption::RunFrequency(_)))
        }));
        let missing_key =
            fcron_evidence_for_table(&result, Subject::uid(1000), SourceRootId::new(9), 0, 4)
                .unwrap();
        assert!(missing_key.iter().all(|row| row.occurrence().is_none()));
        assert!(missing_key.iter().take(2).all(|row| {
            row.presence() == Presence::Unavailable(UnavailableReason::MalformedEvidence)
        }));
        let overflow = fcron_evidence_for_table(
            &result,
            Subject::uid(1000),
            SourceRootId::new(9),
            u32::MAX,
            4,
        )
        .unwrap();
        assert!(overflow.iter().all(|row| row.occurrence().is_none()));
        assert!(overflow.iter().take(2).all(|row| {
            row.presence() == Presence::Unavailable(UnavailableReason::MalformedEvidence)
        }));
    }

    #[test]
    fn source_states_and_safety_are_typed() {
        let empty = b"# no entries\n";
        assert_eq!(
            normalize_fcron_file(
                stat(empty.len()),
                empty,
                stat(empty.len()),
                FcronTableKind::UserSource,
                Some(1000)
            ),
            FcronTableResult::PresentEmpty
        );
        assert_eq!(FcronTableResult::Absent.presence(), Presence::Absent);
        assert!(matches!(
            normalize_fcron_file(
                stat(1),
                &[0xff],
                stat(1),
                FcronTableKind::UserSource,
                Some(1000)
            ),
            FcronTableResult::Unavailable(UnavailableReason::UnsupportedEncoding)
        ));
        let bad = b"@ 0 /bin/true\n";
        assert!(matches!(
            normalize_fcron_file(
                stat(bad.len()),
                bad,
                stat(bad.len()),
                FcronTableKind::UserSource,
                Some(1000)
            ),
            FcronTableResult::Unknown(_)
        ));
        let mut changed = stat(empty.len());
        changed.ino = 77;
        assert!(matches!(
            normalize_fcron_file(
                stat(empty.len()),
                empty,
                changed,
                FcronTableKind::UserSource,
                Some(1000)
            ),
            FcronTableResult::Unavailable(UnavailableReason::ChangedDuringRead)
        ));
    }

    #[test]
    fn authority_is_exact_and_runtime_is_unavailable() {
        let package = ObservedPackageIdentity::new(
            Provider::Fcron,
            "3.4.0",
            "6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee",
            "f4e7fc553cdd70ff4b3b6ac9138b3b7cffab9198b8c266d97af0a87506e0e1b5",
            &["245d7f3c07386bf586bad9452b2399cfaba6f88a8f33e6cd125d632b164e21a2"],
        )
        .unwrap();
        assert!(matches!(
            resolve_fcron_3_4_0_authority(
                &PackageIdentityObservation::Known(package.clone()),
                &fcron_3_4_0_contract_observation(),
            ),
            AuthorityResolution::Resolved(_)
        ));
        assert!(matches!(
            resolve_fcron_3_4_0_authority(
                &PackageIdentityObservation::Unavailable,
                &fcron_3_4_0_contract_observation(),
            ),
            AuthorityResolution::Unresolved(_)
        ));
        let result = FcronTableResult::Present(
            parse_fcron("@daily /bin/true\n", FcronTableKind::UserSource)
                .unwrap()
                .unwrap(),
        );
        let rows =
            fcron_evidence_for_table(&result, Subject::uid(1000), SourceRootId::new(1), 1, 0)
                .unwrap();
        assert!(matches!(
            rows[1].authority(AuthorityRole::SchedulerSemantics),
            AuthorityResolution::Unresolved(_)
        ));
        assert!(
            rows.iter()
                .filter_map(|row| row.occurrence())
                .all(|occurrence| matches!(
                    occurrence.shape(),
                    Some(DefinitionShape::Fcron {
                        schedule: ShapeState::Known(_),
                        command: ShapeState::Unknown(ShapeUnknownReason::NotObserved),
                        context: ShapeState::Unknown(ShapeUnknownReason::NotObserved),
                    })
                ))
        );
        let rows = fcron_evidence_for_table_with_authority(
            &result,
            Subject::uid(1000),
            SourceRootId::new(1),
            1,
            0,
            &PackageIdentityObservation::Known(package.clone()),
            &fcron_3_4_0_contract_observation(),
        )
        .unwrap();
        assert!(matches!(
            rows[1].authority(AuthorityRole::SchedulerSemantics),
            AuthorityResolution::Resolved(_)
        ));
        assert_eq!(
            rows[0].authority(AuthorityRole::AutomationMapping),
            AuthorityResolution::NotClaimed
        );
        assert!(
            rows.iter()
                .all(|row| row.component() != ObservationComponent::Runtime
                    || matches!(row.presence(), Presence::Unknown(_)))
        );
        assert!(matches!(
            resolve_fcron_3_4_1_authority(
                &PackageIdentityObservation::Known(package.clone()),
                &fcron_3_4_1_contract_observation(),
            ),
            AuthorityResolution::Unresolved(_)
        ));
        assert!(matches!(
            resolve_fcron_3_4_1_authority(
                &PackageIdentityObservation::Known(package),
                &fcron_3_4_0_contract_observation(),
            ),
            AuthorityResolution::Unresolved(AuthorityUnknownReason::ExactBasisUnverifiable)
        ));
        assert!(matches!(
            ProviderCatalog::embedded().resolve_observation(
                AuthorityRole::SchedulerSemantics,
                CatalogScope::Provider(Provider::Fcron),
                &fcron_3_4_1_contract_observation(),
            ),
            AuthorityResolution::Resolved(entry)
                if entry.entry_id().as_str() == "fcron.v3.4.1.scheduler.v1"
        ));
    }

    #[test]
    fn fcron_341_changes_only_quoted_command_acceptance() {
        let quoted_with_args = include_bytes!("../tests/fixtures/fcron/3.4.1/quoted-command.orig");
        assert!(matches!(
            normalize_fcron_file(
                stat(quoted_with_args.len()),
                quoted_with_args,
                stat(quoted_with_args.len()),
                FcronTableKind::UserSource,
                Some(1000),
            ),
            FcronTableResult::Unknown(ObservationUnknownReason::MalformedSyntax)
        ));
        let observed = normalize_fcron_3_4_1_file(
            stat(quoted_with_args.len()),
            quoted_with_args,
            stat(quoted_with_args.len()),
            FcronTableKind::UserSource,
            Some(1000),
        );
        assert!(matches!(observed.raw_state(), FcronTableResult::Present(_)));
        assert!(!format!("{:?}", observed).contains("echo"));
        let empty = b"# no entries\n";
        assert_eq!(
            normalize_fcron_3_4_1_file(
                stat(empty.len()),
                empty,
                stat(empty.len()),
                FcronTableKind::UserSource,
                Some(1000),
            ),
            Fcron341TableResult(FcronTableResult::PresentEmpty)
        );
        let malformed = b"@daily\n";
        assert!(matches!(
            normalize_fcron_3_4_1_file(
                stat(malformed.len()),
                malformed,
                stat(malformed.len()),
                FcronTableKind::UserSource,
                Some(1000),
            ),
            Fcron341TableResult(FcronTableResult::Unknown(_))
        ));
        for malformed in [b"@daily\n".as_slice(), b"%daily\n".as_slice()] {
            let old = normalize_fcron_file(
                stat(malformed.len()),
                malformed,
                stat(malformed.len()),
                FcronTableKind::UserSource,
                Some(1000),
            );
            let new = normalize_fcron_3_4_1_file(
                stat(malformed.len()),
                malformed,
                stat(malformed.len()),
                FcronTableKind::UserSource,
                Some(1000),
            );
            assert_eq!(old.presence(), new.presence());
        }
        let empty_quoted = b"@daily \"\"\n";
        assert!(matches!(
            normalize_fcron_file(
                stat(empty_quoted.len()),
                empty_quoted,
                stat(empty_quoted.len()),
                FcronTableKind::UserSource,
                Some(1000),
            ),
            FcronTableResult::Unknown(ObservationUnknownReason::MalformedSyntax)
        ));
        assert!(matches!(
            normalize_fcron_3_4_1_file(
                stat(empty_quoted.len()),
                empty_quoted,
                stat(empty_quoted.len()),
                FcronTableKind::UserSource,
                Some(1000),
            ),
            Fcron341TableResult(FcronTableResult::Present(_))
        ));
        let lone_quote = b"@daily \"";
        assert!(matches!(
            normalize_fcron_file(
                stat(lone_quote.len()),
                lone_quote,
                stat(lone_quote.len()),
                FcronTableKind::UserSource,
                Some(1000),
            ),
            FcronTableResult::Unknown(ObservationUnknownReason::MalformedSyntax)
        ));
        let quoted_spaces = b"@daily \"   \"";
        assert!(matches!(
            normalize_fcron_file(
                stat(quoted_spaces.len()),
                quoted_spaces,
                stat(quoted_spaces.len()),
                FcronTableKind::UserSource,
                Some(1000),
            ),
            FcronTableResult::Present(_)
        ));
        let rows = fcron_3_4_1_evidence_for_table(
            &normalize_fcron_3_4_1_file(
                stat(quoted_with_args.len()),
                quoted_with_args,
                stat(quoted_with_args.len()),
                FcronTableKind::UserSource,
                Some(1000),
            ),
            Subject::uid(1000),
            SourceRootId::new(1),
            1,
            0,
        )
        .unwrap();
        assert!(rows.iter().all(|row| {
            row.component() != ObservationComponent::Runtime
                || matches!(row.presence(), Presence::Unknown(_))
        }));
        assert_eq!(
            rows[0].authority(AuthorityRole::AutomationMapping),
            AuthorityResolution::NotClaimed
        );
        assert!(matches!(
            normalize_fcron_3_4_1_file(
                stat(quoted_with_args.len()),
                quoted_with_args,
                stat(quoted_with_args.len()),
                FcronTableKind::SystemSource,
                None,
            ),
            Fcron341TableResult(FcronTableResult::Unavailable(
                UnavailableReason::UnsafeObjectType,
            ))
        ));

        let forms = b"@ 1h \"/bin/echo\" hello\n& 0 5 * * * \"/bin/echo\" hello\n%daily * 5 \"/bin/echo\" hello\n@daily \"/bin/echo\" hello\n";
        assert!(matches!(
            normalize_fcron_3_4_1_file(
                stat(forms.len()),
                forms,
                stat(forms.len()),
                FcronTableKind::UserSource,
                Some(1000),
            ),
            Fcron341TableResult(FcronTableResult::Present(_))
        ));
        let stable_inputs: &[&[u8]] = &[
            b"@ 1h /bin/true\n",
            b"%daily * 5 /bin/true\n",
            b"0 5 * * * /bin/true\n",
            b"TZ='Europe/Tokyo'\n@daily /bin/true\n",
        ];
        for stable in stable_inputs {
            let old = normalize_fcron_file(
                stat(stable.len()),
                stable,
                stat(stable.len()),
                FcronTableKind::UserSource,
                Some(1000),
            );
            let new = normalize_fcron_3_4_1_file(
                stat(stable.len()),
                stable,
                stat(stable.len()),
                FcronTableKind::UserSource,
                Some(1000),
            );
            assert_eq!(old.presence(), new.presence());
            assert_eq!(old.schedule(), new.raw_state().schedule());
        }
        let fully_quoted = b"@daily \"/bin/echo hello\"\n";
        assert!(matches!(
            normalize_fcron_file(
                stat(fully_quoted.len()),
                fully_quoted,
                stat(fully_quoted.len()),
                FcronTableKind::UserSource,
                Some(1000),
            ),
            FcronTableResult::Present(_)
        ));
    }

    #[test]
    fn official_shortcuts_bare_calendar_and_option_boundaries_are_preserved() {
        let bare = b"0 5 * * * /bin/true";
        let bare_result = normalize_fcron_file(
            stat(bare.len()),
            bare,
            stat(bare.len()),
            FcronTableKind::UserSource,
            Some(1000),
        );
        assert!(matches!(bare_result, FcronTableResult::Present(_)));
        let shorthand = parse_fcron("@5 1h /bin/true\n", FcronTableKind::UserSource)
            .unwrap()
            .unwrap();
        assert!(matches!(
            shorthand.entries()[0].kind(),
            FcronEntryKind::Elapsed { frequency } if frequency.seconds() == 3_600
        ));
        assert!(
            shorthand.entries()[0]
                .options()
                .options()
                .iter()
                .any(|option| matches!(
                    option,
                    FcronOption::First(value) if value.seconds() == 300
                ))
        );
        let stepped = parse_fcron("0 */2 * * * /bin/true\n", FcronTableKind::UserSource)
            .unwrap()
            .unwrap();
        assert!(matches!(
            stepped.entries()[0].kind(),
            FcronEntryKind::Calendar(fields)
                if matches!(
                    fields.fields()[1].atoms(),
                    [FcronFieldAtom::Range { start: 0, end: 23, step: 2, excluded }] if excluded.is_empty()
                )
        ));
        let separated_ampersand = parse_fcron(
            "& 05,35 12-14 * * * /bin/true\n",
            FcronTableKind::UserSource,
        )
        .unwrap()
        .unwrap();
        assert!(matches!(
            separated_ampersand.entries()[0].kind(),
            FcronEntryKind::Calendar(fields)
                if matches!(fields.fields()[0].atoms(), [FcronFieldAtom::Value(5), FcronFieldAtom::Value(35)])
        ));
        let glued_frequency = parse_fcron("&7 0 5 * * * /bin/true\n", FcronTableKind::UserSource)
            .unwrap()
            .unwrap();
        assert!(
            glued_frequency.entries()[0]
                .options()
                .options()
                .iter()
                .any(|option| matches!(option, FcronOption::RunFrequency(7)))
        );
        let vixie_daily = parse_fcron("@daily /bin/true\n", FcronTableKind::UserSource)
            .unwrap()
            .unwrap();
        assert!(matches!(
            vixie_daily.entries()[0].kind(),
            FcronEntryKind::Calendar(fields)
                if matches!(fields.fields()[0].atoms(), [FcronFieldAtom::Value(0)])
                    && matches!(fields.fields()[1].atoms(), [FcronFieldAtom::Value(0)])
                    && matches!(fields.fields()[2].atoms(), [FcronFieldAtom::Any])
        ));
        let aliases = parse_fcron(
            "!s\n&r(7) 0 5 * * * /bin/true\n@u(5h) 1d /bin/true\n",
            FcronTableKind::UserSource,
        )
        .unwrap()
        .unwrap();
        assert!(aliases.entries().iter().any(|entry| {
            entry
                .options()
                .options()
                .iter()
                .any(|option| matches!(option, FcronOption::Serial(true)))
        }));
        assert!(aliases.entries().iter().any(|entry| {
            entry
                .options()
                .options()
                .iter()
                .any(|option| matches!(option, FcronOption::RunFrequency(7)))
        }));
        assert!(aliases.entries().iter().any(|entry| {
            entry.options().options().iter().any(
                |option| matches!(option, FcronOption::Until(value) if value.seconds() == 18_000),
            )
        }));
        for line in [
            b"@reboot /bin/true\n".as_slice(),
            b"@resume /bin/true\n".as_slice(),
            b"@yearly /bin/true\n".as_slice(),
            b"@annually /bin/true\n".as_slice(),
        ] {
            assert!(matches!(
                normalize_fcron_file(
                    stat(line.len()),
                    line,
                    stat(line.len()),
                    FcronTableKind::UserSource,
                    Some(1000)
                ),
                FcronTableResult::Present(_)
            ));
        }
        let unsupported_periodic = b"%yearly * * * /bin/true\n";
        assert!(matches!(
            normalize_fcron_file(
                stat(unsupported_periodic.len()),
                unsupported_periodic,
                stat(unsupported_periodic.len()),
                FcronTableKind::UserSource,
                Some(1000)
            ),
            FcronTableResult::Unknown(ObservationUnknownReason::UnsupportedSyntax)
        ));
        let periodic_run_frequency = b"%daily,r(7) * 5 /bin/true\n";
        assert!(matches!(
            normalize_fcron_file(
                stat(periodic_run_frequency.len()),
                periodic_run_frequency,
                stat(periodic_run_frequency.len()),
                FcronTableKind::UserSource,
                Some(1000)
            ),
            FcronTableResult::Unknown(ObservationUnknownReason::UnsupportedSyntax)
        ));
        let inherited_run_frequency = parse_fcron(
            "!runfreq(7),s\n%daily * 5 /bin/true\n0 6 * * * /bin/true\n",
            FcronTableKind::UserSource,
        )
        .unwrap()
        .unwrap();
        assert!(
            inherited_run_frequency.entries()[0]
                .options()
                .options()
                .iter()
                .all(|option| !matches!(option, FcronOption::RunFrequency(_)))
        );
        assert!(
            inherited_run_frequency.entries()[0]
                .options()
                .options()
                .iter()
                .any(|option| matches!(option, FcronOption::Serial(true)))
        );
        assert!(
            inherited_run_frequency.entries()[1]
                .options()
                .options()
                .iter()
                .any(|option| matches!(option, FcronOption::RunFrequency(7)))
        );
        let named_exclusion =
            parse_fcron("0 5 * * MON~MON /bin/true\n", FcronTableKind::UserSource)
                .unwrap()
                .unwrap();
        assert!(matches!(
            named_exclusion.entries()[0].kind(),
            FcronEntryKind::Calendar(fields)
                if matches!(
                    fields.fields()[4].atoms(),
                    [FcronFieldAtom::Range { start: 1, end: 1, step: 1, excluded }] if excluded == &[1]
                )
        ));
        let full_range_periodic = b"%hours * 0-23 * * * /bin/true\n";
        assert!(matches!(
            normalize_fcron_file(
                stat(full_range_periodic.len()),
                full_range_periodic,
                stat(full_range_periodic.len()),
                FcronTableKind::UserSource,
                Some(1000)
            ),
            FcronTableResult::Unknown(ObservationUnknownReason::UnsupportedSyntax)
        ));
        let options = b"!first(0),until(1s)\n%nightly,lavg(.5,2.5,255) * 1 /bin/true\n";
        assert!(matches!(
            normalize_fcron_file(
                stat(options.len()),
                options,
                stat(options.len()),
                FcronTableKind::UserSource,
                Some(1000)
            ),
            FcronTableResult::Present(_)
        ));
        let aliases = b"!lavg1(1.0),lavg5(2.0),lavg15(255.0)\n@daily /bin/true\n";
        let FcronTableResult::Present(schedule) = normalize_fcron_file(
            stat(aliases.len()),
            aliases,
            stat(aliases.len()),
            FcronTableKind::UserSource,
            Some(1000),
        ) else {
            panic!()
        };
        assert!(schedule.options().options().iter().any(|option| matches!(
            option,
            FcronOption::LavgOne { slot: 1, value } if value.tenths() == 10
        )));
        assert!(schedule.options().options().iter().any(|option| matches!(
            option,
            FcronOption::LavgOne { slot: 5, value } if value.tenths() == 20
        )));
        assert!(schedule.options().options().iter().any(|option| matches!(
            option,
            FcronOption::LavgOne { slot: 15, value } if value.tenths() == 2_550
        )));
        let rounded = parse_fcron(
            "!lavg(0.95,1.04,1.55)\n@daily /bin/true\n",
            FcronTableKind::UserSource,
        )
        .unwrap()
        .unwrap();
        assert!(rounded.options().options().iter().any(|option| matches!(
            option,
            FcronOption::Lavg(values)
                if values == &[
                    Some(FcronLoadAverage::from_tenths(10)),
                    Some(FcronLoadAverage::from_tenths(10)),
                    Some(FcronLoadAverage::from_tenths(16)),
                ]
        )));
        assert!(matches!(
            parse_fcron("!until(0)\n@daily /bin/true\n", FcronTableKind::UserSource),
            Ok(Some(_))
        ));
        let descending = b"10-5 * * * * /bin/true\n";
        assert!(matches!(
            normalize_fcron_file(
                stat(descending.len()),
                descending,
                stat(descending.len()),
                FcronTableKind::UserSource,
                Some(1000)
            ),
            FcronTableResult::Unknown(ObservationUnknownReason::UnsupportedSyntax)
        ));
        let rows = fcron_evidence_for_table(
            &FcronTableResult::PresentEmpty,
            Subject::uid(1000),
            SourceRootId::new(1),
            1,
            0,
        )
        .unwrap();
        assert!(rows.iter().all(|row| row.occurrence().is_some()));
    }

    #[cfg(unix)]
    #[test]
    #[allow(deprecated)]
    fn production_path_requires_explicit_spool_root_and_rejects_parent_links() {
        use std::fs;
        use std::os::unix::fs::{PermissionsExt, symlink};
        let temp_root = if Path::new("/private/tmp").is_dir() {
            Path::new("/private/tmp")
        } else {
            Path::new("/tmp")
        };
        let root = temp_root.join(format!("nix-fcron-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let source = FcronSpoolRoot::new(&root)
            .unwrap()
            .user_source("alice")
            .unwrap();
        assert!(matches!(
            FcronSpoolRoot::new(&root).unwrap().user_source("systab"),
            Err(FcronPathError::InvalidUser)
        ));
        fs::write(root.join("alice.orig"), b"@daily /bin/true\n").unwrap();
        fs::set_permissions(root.join("alice.orig"), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            read_fcron_source(&source, None),
            FcronTableResult::Present(_)
        ));
        assert!(matches!(
            read_fcron_3_4_1_source(&source, None).raw_state(),
            FcronTableResult::Present(_)
        ));
        let missing = FcronSpoolRoot::new(&root)
            .unwrap()
            .user_source("missing")
            .unwrap();
        assert_eq!(
            read_fcron_3_4_1_source(&missing, None).raw_state(),
            &FcronTableResult::Absent
        );
        let system = FcronSpoolRoot::new(&root).unwrap().system_source();
        assert!(matches!(
            read_fcron_3_4_1_source(&system, None).raw_state(),
            FcronTableResult::Unavailable(UnavailableReason::UnsafeObjectType)
        ));
        assert!(matches!(
            read_fcron_file(&root.join("new.alice"), FcronTableKind::UserSource, None),
            FcronTableResult::Unavailable(UnavailableReason::UnsafeObjectType)
        ));
        let linked = root.join("linked");
        let target = root.join("target");
        fs::create_dir_all(&target).unwrap();
        symlink(&target, &linked).unwrap();
        assert!(matches!(
            FcronSpoolRoot::new(&linked),
            Err(FcronPathError::UnsafeRoot)
        ));
    }
}
