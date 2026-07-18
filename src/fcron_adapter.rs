//! Read-only normalization of fcron 3.4.0 source tables.
//!
//! The daemon's human-readable source is `<user>.orig` (or the explicitly
//! configured `systab.orig`).  fcron itself ignores dotted files at runtime;
//! this adapter therefore reports only configuration/schedule evidence and
//! never treats a source table as a loaded or executed job.

use std::io::{self, Read};
use std::{
    fmt,
    path::{Path, PathBuf},
};

use crate::catalog::{
    AuthorityIdentityObservation, AuthorityResolution, AuthorityRole, CatalogScope,
    ObservedAuthorityIdentity, ProviderCatalog,
};
use crate::evidence::{
    CaptureSequence, DefinitionOccurrence, InputError, ObservationComponent,
    ObservationUnknownReason, Presence, Provider, ProviderEvidence, ProviderEvidenceSet,
    ProviderLogicalKey, SourceOccurrenceKey, SourceRoot, SourceRootId, Subject, UnavailableReason,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FcronPathError {
    NotAbsolute,
    UnsafeComponent,
    MissingRoot,
    UnsafeRoot,
    InvalidUser,
}

/// A caller-provided, existing `fcrontabs` root.  The root is intentionally
/// required before a production source path can be constructed: the adapter
/// never assumes the distro default and never discovers users or configuration.
#[derive(Clone, PartialEq, Eq)]
pub struct FcronSpoolRoot(PathBuf);

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
        Ok(Self(path.to_owned()))
    }

    pub fn user_source(&self, user: &str) -> Result<FcronSourcePath, FcronPathError> {
        validate_component(user)?;
        Ok(FcronSourcePath {
            path: self.0.join(format!("{user}.orig")),
            kind: FcronTableKind::UserSource,
        })
    }

    pub fn system_source(&self) -> FcronSourcePath {
        FcronSourcePath {
            path: self.0.join("systab.orig"),
            kind: FcronTableKind::SystemSource,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct FcronSourcePath {
    path: PathBuf,
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

impl FcronTableResult {
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
    match parse_fcron(text, kind) {
        Ok(None) => FcronTableResult::PresentEmpty,
        Ok(Some(schedule)) => FcronTableResult::Present(schedule),
        Err(reason) => FcronTableResult::Unknown(reason),
    }
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
    read_fcron_file_inner(&source.path, source.kind, expected_owner)
}

#[cfg(unix)]
pub fn read_fcron_file(
    path: &Path,
    kind: FcronTableKind,
    expected_owner: Option<u32>,
) -> FcronTableResult {
    if !allowed_path(path, kind) || safe_parent_chain(path).is_none() {
        return FcronTableResult::Unavailable(UnavailableReason::UnsafeObjectType);
    }
    read_fcron_file_inner(path, kind, expected_owner)
}

#[cfg(unix)]
fn read_fcron_file_inner(
    path: &Path,
    kind: FcronTableKind,
    expected_owner: Option<u32>,
) -> FcronTableResult {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    let lstat = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return FcronTableResult::Absent,
        Err(error) => return FcronTableResult::Unavailable(io_reason(error)),
    };
    if !lstat.file_type().is_file() {
        return FcronTableResult::Unavailable(UnavailableReason::UnsafeObjectType);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if safe_parent_chain(path) != Some(lstat.dev()) {
            return FcronTableResult::Unavailable(UnavailableReason::UnsafeObjectType);
        }
    }
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return FcronTableResult::Absent,
        Err(error) => return FcronTableResult::Unavailable(io_reason(error)),
    };
    let before = match file.metadata() {
        Ok(metadata) => stat_from_metadata(&metadata),
        Err(error) => return FcronTableResult::Unavailable(io_reason(error)),
    };
    if !stat_from_metadata(&lstat).same_generation(before) {
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
    normalize_fcron_file(before, &bytes, after, kind, expected_owner)
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

fn allowed_path(path: &Path, kind: FcronTableKind) -> bool {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return false;
    }
    let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !name.ends_with(".orig")
        || name.len() <= ".orig".len()
        || name.chars().any(char::is_control)
        || name.contains('/')
    {
        return false;
    }
    match kind {
        FcronTableKind::UserSource => name != "systab.orig",
        FcronTableKind::SystemSource => name == "systab.orig",
    }
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

fn parse_fcron(
    text: &str,
    kind: FcronTableKind,
) -> Result<Option<FcronSchedule>, ObservationUnknownReason> {
    let mut context = ParseContext {
        options: FcronOptionSet::default(),
        timezone: None,
        entries: Vec::new(),
    };
    for line in logical_lines(text)? {
        parse_line(&line, &mut context)?;
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

fn parse_line(line: &str, context: &mut ParseContext) -> Result<(), ObservationUnknownReason> {
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
        Some(b'@') => return parse_at_line(&line[1..], context),
        Some(b'&') => return parse_calendar_line(&line[1..], context, true),
        Some(b'%') => return parse_periodic_line(&line[1..], context),
        Some(b'0'..=b'9') | Some(b'*') => return parse_calendar_line(line, context, false),
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

fn parse_at_line(rest: &str, context: &mut ParseContext) -> Result<(), ObservationUnknownReason> {
    let rest = rest.trim_start();
    let mut fields = rest.splitn(2, char::is_whitespace);
    let head = fields.next().unwrap_or("");
    let tail = fields.next().unwrap_or("").trim_start();
    if head == "reboot" || head == "resume" {
        if tail.is_empty() {
            return Err(ObservationUnknownReason::MalformedSyntax);
        }
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
        context.entries.push(FcronEntry::new(
            FcronEntryKind::Periodic {
                keyword,
                fields: None,
            },
            context.options.clone(),
        ));
        return Ok(());
    }
    let (options, frequency_token, command) = if head.is_empty() {
        let mut parts = rest.splitn(2, char::is_whitespace);
        let frequency = parts.next().unwrap_or("");
        (Vec::new(), frequency, parts.next().unwrap_or("").trim())
    } else if parse_time_value(head).is_ok() {
        (Vec::new(), head, tail)
    } else {
        let options = parse_options(head)?;
        let mut parts = tail.splitn(2, char::is_whitespace);
        let frequency = parts.next().unwrap_or("");
        (options, frequency, parts.next().unwrap_or("").trim())
    };
    if command.is_empty() {
        return Err(ObservationUnknownReason::MalformedSyntax);
    }
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

fn parse_calendar_line(
    rest: &str,
    context: &mut ParseContext,
    allow_frequency: bool,
) -> Result<(), ObservationUnknownReason> {
    let rest = rest.trim_start();
    let mut tokens = rest.split_whitespace();
    let first = tokens
        .next()
        .ok_or(ObservationUnknownReason::MalformedSyntax)?;
    let (local_options, frequency) = if allow_frequency && first.chars().all(|c| c.is_ascii_digit())
    {
        let value = first
            .parse::<u32>()
            .map_err(|_| ObservationUnknownReason::MalformedSyntax)?;
        if value < 2 {
            return Err(ObservationUnknownReason::UnsupportedSyntax);
        }
        (Vec::new(), Some(value))
    } else if allow_frequency
        && first != "*"
        && !first.starts_with("*/")
        && (first.contains(',') || first.contains('(') || is_option_name(first))
    {
        (parse_options(first)?, None)
    } else {
        (Vec::new(), None)
    };
    let mut field_tokens = if !allow_frequency || first == "*" || first.starts_with("*/") {
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
    if field_tokens.next().is_none() {
        return Err(ObservationUnknownReason::MalformedSyntax);
    }
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
        if index < needed {
            let token = tokens
                .next()
                .ok_or(ObservationUnknownReason::MalformedSyntax)?;
            fields.push(
                parse_field(token, min, max, names)
                    .map_err(|_| ObservationUnknownReason::UnsupportedSyntax)?,
            );
        } else {
            fields.push(FcronTimeField::new(vec![FcronFieldAtom::Any]).expect("Any is nonempty"));
        }
    }
    if tokens.next().is_none() {
        return Err(ObservationUnknownReason::MalformedSyntax);
    }
    let fields: [FcronTimeField; 5] = fields.try_into().expect("five calendar fields");
    let options = context.options.merge(&local_options);
    if matches!(
        keyword,
        FcronPeriodicKeyword::Minutes
            | FcronPeriodicKeyword::Hours
            | FcronPeriodicKeyword::Days
            | FcronPeriodicKeyword::Months
            | FcronPeriodicKeyword::DayOfWeek
    ) && fields.iter().all(field_is_any)
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
            "runfreq" => {
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
            "serial" => FcronOption::Serial(bool_value(true)?),
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
            "until" => {
                let value =
                    parse_time_value(argument.ok_or(ObservationUnknownReason::MalformedSyntax)?)?;
                if value.seconds() == 0 {
                    return Err(ObservationUnknownReason::MalformedSyntax);
                }
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
        let (whole, fraction) = part.split_once('.').unwrap_or((part, "0"));
        if fraction.len() != 1 {
            return Err(ObservationUnknownReason::MalformedSyntax);
        }
        let whole = whole
            .parse::<u16>()
            .map_err(|_| ObservationUnknownReason::MalformedSyntax)?;
        let fraction = fraction
            .parse::<u16>()
            .map_err(|_| ObservationUnknownReason::MalformedSyntax)?;
        let tenths = whole
            .checked_mul(10)
            .and_then(|value| value.checked_add(fraction))
            .filter(|value| *value <= 2_550)
            .ok_or(ObservationUnknownReason::MalformedSyntax)?;
        values[index] = Some(FcronLoadAverage::from_tenths(tenths));
    }
    Ok(values)
}

fn parse_single_lavg(value: &str) -> Result<FcronLoadAverage, ObservationUnknownReason> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, "0"));
    if fraction.len() != 1 {
        return Err(ObservationUnknownReason::MalformedSyntax);
    }
    let whole = whole
        .parse::<u16>()
        .map_err(|_| ObservationUnknownReason::MalformedSyntax)?;
    let fraction = fraction
        .parse::<u16>()
        .map_err(|_| ObservationUnknownReason::MalformedSyntax)?;
    let tenths = whole
        .checked_mul(10)
        .and_then(|value| value.checked_add(fraction))
        .filter(|value| *value <= 2_550)
        .ok_or(ObservationUnknownReason::MalformedSyntax)?;
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
            if excluded.is_empty() {
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
            (
                parse_value(start, min, max, names)?,
                parse_value(end, min, max, names)?,
            )
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
            Some(value) => FcronFieldAtom::Name(value),
            None if start == end && excluded.is_empty() => FcronFieldAtom::Value(start),
            None => FcronFieldAtom::Range {
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

fn field_is_any(field: &FcronTimeField) -> bool {
    matches!(field.atoms(), [FcronFieldAtom::Any])
}

fn fcron_scheduler_authority() -> AuthorityResolution {
    let identity = ObservedAuthorityIdentity::contract_with_fingerprint(
        "yo8192/fcron",
        "8198d4b90690fb0f53cca931b6e9bb6d4b9e6f83",
        "doc/en/fcrontab.5.sgml",
        Some("3.4.0"),
        None,
        Some("fcron-3.4.0-v1"),
    );
    let Ok(identity) = identity else {
        return AuthorityResolution::Unresolved(
            crate::catalog::AuthorityUnknownReason::IdentityMalformed,
        );
    };
    ProviderCatalog::embedded().resolve_observation(
        AuthorityRole::SchedulerSemantics,
        CatalogScope::Provider(Provider::Fcron),
        &AuthorityIdentityObservation::Known(identity),
    )
}

pub fn resolve_fcron_3_4_0_authority() -> AuthorityResolution {
    fcron_scheduler_authority()
}

/// Convert source-only fcron configuration into report evidence. Runtime,
/// Activity, Runs, and LastResult remain Unknown because the daemon ignores
/// `.orig` files and the adapter never reads compiled state or logs.
pub fn fcron_evidence_for_table(
    result: &FcronTableResult,
    subject: Subject,
    source_id: SourceRootId,
    ordinal: u32,
    capture: u32,
) -> Result<Vec<ProviderEvidence>, InputError> {
    let occurrence = result.schedule().map(|_| {
        DefinitionOccurrence::new(
            ProviderLogicalKey::Anonymous,
            SourceOccurrenceKey::new(SourceRoot::FcronTable(source_id), ordinal),
            CaptureSequence::new(capture),
        )
    });
    let mut rows = Vec::new();
    for component in [
        ObservationComponent::Configuration,
        ObservationComponent::Schedule,
    ] {
        let mut row = match occurrence.as_ref() {
            Some(occurrence) => ProviderEvidence::with_occurrence(
                Provider::Fcron,
                subject,
                component,
                result.presence(),
                occurrence.clone(),
            )?,
            None => ProviderEvidence::new(Provider::Fcron, subject, component, result.presence())?,
        };
        if component == ObservationComponent::Schedule
            && let Some(schedule) = result.schedule()
        {
            row = row.with_schedule(Schedule::Fcron(schedule.clone()))?;
            row = row.with_authority(
                AuthorityRole::SchedulerSemantics,
                fcron_scheduler_authority(),
            )?;
        }
        rows.push(row);
    }
    for component in [
        ObservationComponent::Runtime,
        ObservationComponent::Activity,
        ObservationComponent::Runs,
        ObservationComponent::LastResult,
    ] {
        rows.push(match occurrence.as_ref() {
            Some(occurrence) => ProviderEvidence::with_occurrence(
                Provider::Fcron,
                subject,
                component,
                Presence::Unknown(ObservationUnknownReason::UnsupportedSyntax),
                occurrence.clone(),
            )?,
            None => ProviderEvidence::new(
                Provider::Fcron,
                subject,
                component,
                Presence::Unknown(ObservationUnknownReason::UnsupportedSyntax),
            )?,
        });
    }
    Ok(rows)
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

#[cfg(unix)]
#[allow(dead_code)]
fn _read_path_is_fixture_safe(path: &Path) -> bool {
    allowed_path(path, FcronTableKind::UserSource)
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
        assert!(matches!(
            resolve_fcron_3_4_0_authority(),
            AuthorityResolution::Resolved(_)
        ));
        let result = FcronTableResult::Present(
            parse_fcron("@daily /bin/true\n", FcronTableKind::UserSource)
                .unwrap()
                .unwrap(),
        );
        let rows =
            fcron_evidence_for_table(&result, Subject::uid(1000), SourceRootId::new(1), 1, 0)
                .unwrap();
        assert_eq!(
            rows[0].authority(AuthorityRole::AutomationMapping),
            AuthorityResolution::NotClaimed
        );
        assert!(
            rows.iter()
                .all(|row| row.component() != ObservationComponent::Runtime
                    || matches!(row.presence(), Presence::Unknown(_)))
        );
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
        let options = b"!first(0),until(1s)\n%nightly,lavg(1,2.5,255) * 1 /bin/true\n";
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
        let rows = fcron_evidence_for_table(
            &FcronTableResult::PresentEmpty,
            Subject::uid(1000),
            SourceRootId::new(1),
            1,
            0,
        )
        .unwrap();
        assert!(rows.iter().all(|row| row.occurrence().is_none()));
    }

    #[cfg(unix)]
    #[test]
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
        fs::write(root.join("alice.orig"), b"@daily /bin/true\n").unwrap();
        fs::set_permissions(root.join("alice.orig"), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            read_fcron_source(&source, None),
            FcronTableResult::Present(_)
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
