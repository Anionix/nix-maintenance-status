use std::io::{self, Read};
use std::path::Path;

use crate::evidence::{
    CaptureSequence, DefinitionOccurrence, DefinitionShape, InputError, ObservationComponent,
    ObservationUnknownReason, Presence, Provider, ProviderEvidence, ProviderLogicalKey, ShapeState,
    ShapeUnknownReason, SourceOccurrenceKey, SourceRoot, SourceRootId, Subject, UnavailableReason,
};
use crate::report::{
    CronieCommand, CronieEntry, CronieFieldAtom, CronieSchedule, CronieTimeField, CronieUserField,
    Schedule,
};

pub(crate) const MAX_CRONIE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CronieTableKind {
    System,
    UserSpool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CronieFileStat {
    regular: bool,
    mode: u32,
    owner: u32,
    nlink: u64,
    dev: u64,
    ino: u64,
    size: u64,
    mtime: (i64, i64),
}

impl CronieFileStat {
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
pub enum CronieTableResult {
    Absent,
    PresentEmpty,
    Present(CronieSchedule),
    Unknown(ObservationUnknownReason),
    Unavailable(UnavailableReason),
}

impl CronieTableResult {
    pub const fn presence(&self) -> Presence {
        match self {
            Self::Absent => Presence::Absent,
            Self::PresentEmpty => Presence::PresentEmpty,
            Self::Present(_) => Presence::Present,
            Self::Unknown(reason) => Presence::Unknown(*reason),
            Self::Unavailable(reason) => Presence::Unavailable(*reason),
        }
    }
    pub fn schedule(&self) -> Option<&CronieSchedule> {
        match self {
            Self::Present(schedule) => Some(schedule),
            _ => None,
        }
    }
}

// LLM contract: only a bounded regular file with stable (dev, ino, size,
// mtime, nlink), owner-read-only mode, expected owner, and UTF-8 Cronie syntax
// may become Present/PresentEmpty. Missing is Absent; unsafe, unreadable,
// malformed bytes, over-limit, and changed generations are Unavailable;
// unsupported syntax is explicit Unknown and never Absent. This seam performs
// no command, lock, user switch, network, telemetry, write, or GC.
pub fn normalize_cronie_file(
    before: CronieFileStat,
    bytes: &[u8],
    after: CronieFileStat,
    kind: CronieTableKind,
    expected_owner: Option<u32>,
) -> CronieTableResult {
    if bytes.len() > MAX_CRONIE_BYTES {
        return CronieTableResult::Unavailable(UnavailableReason::ResourceLimitExceeded);
    }
    if !before.same_generation(after)
        || before.size != bytes.len() as u64
        || !before.regular
        || !after.regular
        || before.nlink != 1
        || after.nlink != 1
        || (before.mode & 0o7533) != 0o400
        || (after.mode & 0o7533) != 0o400
        || expected_owner.is_some_and(|owner| before.owner != owner)
        || expected_owner.is_some_and(|owner| after.owner != owner)
    {
        return CronieTableResult::Unavailable(
            if !before.same_generation(after) || before.size != bytes.len() as u64 {
                UnavailableReason::ChangedDuringRead
            } else {
                UnavailableReason::UnsafeObjectType
            },
        );
    }
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => return CronieTableResult::Unavailable(UnavailableReason::UnsupportedEncoding),
    };
    if !text.is_empty() && !text.ends_with('\n') {
        return CronieTableResult::Unknown(ObservationUnknownReason::MalformedSyntax);
    }
    match parse_cronie(
        text,
        kind,
        kind == CronieTableKind::System || expected_owner == Some(0),
    ) {
        Ok(None) => CronieTableResult::PresentEmpty,
        Ok(Some(schedule)) => CronieTableResult::Present(schedule),
        Err(reason) => CronieTableResult::Unknown(reason),
    }
}

#[cfg(unix)]
/// Reads only `/etc/crontab`, one direct `/etc/cron.d` child, or one direct
/// `/var/spool/cron` child selected by the caller's bounded local enumeration.
pub fn read_cronie_file(
    path: &Path,
    kind: CronieTableKind,
    expected_owner: Option<u32>,
) -> CronieTableResult {
    if !allowed_path(path, kind) {
        return CronieTableResult::Unavailable(UnavailableReason::UnsafeObjectType);
    }
    read_cronie_file_inner(path, kind, expected_owner)
}

#[cfg(all(test, unix))]
fn read_fixture_file(
    path: &Path,
    kind: CronieTableKind,
    expected_owner: Option<u32>,
) -> CronieTableResult {
    read_cronie_file_inner(path, kind, expected_owner)
}

#[cfg(unix)]
fn read_cronie_file_inner(
    path: &Path,
    kind: CronieTableKind,
    expected_owner: Option<u32>,
) -> CronieTableResult {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    let path_metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return CronieTableResult::Absent,
        Err(error) => return CronieTableResult::Unavailable(io_reason(error)),
    };
    if !path_metadata.file_type().is_file() {
        return CronieTableResult::Unavailable(UnavailableReason::UnsafeObjectType);
    }
    // lstat classifies an existing link; no-follow + nonblocking descriptor
    // flags close replacement races before descriptor-side metadata checks.
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return CronieTableResult::Absent,
        Err(error) => return CronieTableResult::Unavailable(io_reason(error)),
    };
    let before = match file.metadata() {
        Ok(metadata) => stat_from_metadata(&metadata),
        Err(error) => return CronieTableResult::Unavailable(io_reason(error)),
    };
    // Compare the initial lstat generation with descriptor metadata before
    // trusting the opened file. A regular-file replacement between those
    // operations must remain unavailable even when the replacement is safe.
    let initial = stat_from_metadata(&path_metadata);
    if !initial.same_generation(before) {
        return CronieTableResult::Unavailable(UnavailableReason::ChangedDuringRead);
    }
    if before.size > MAX_CRONIE_BYTES as u64 {
        return CronieTableResult::Unavailable(UnavailableReason::ResourceLimitExceeded);
    }
    let mut bytes = Vec::with_capacity(before.size as usize);
    let read_result = (&mut &file)
        .take((MAX_CRONIE_BYTES + 1) as u64)
        .read_to_end(&mut bytes);
    if let Err(error) = read_result {
        return CronieTableResult::Unavailable(io_reason(error));
    }
    let after = match file.metadata() {
        Ok(metadata) => stat_from_metadata(&metadata),
        Err(error) => return CronieTableResult::Unavailable(io_reason(error)),
    };
    normalize_cronie_file(before, &bytes, after, kind, expected_owner)
}

fn allowed_path(path: &Path, kind: CronieTableKind) -> bool {
    if path.components().any(|component| {
        matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        )
    }) {
        return false;
    }
    let parent = path.parent();
    match kind {
        CronieTableKind::System => {
            if path == Path::new("/etc/crontab") {
                return true;
            }
            if parent != Some(Path::new("/etc/cron.d")) {
                return false;
            }
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                return false;
            };
            !name.is_empty()
                && !name.starts_with('.')
                && !name.starts_with('#')
                && !name.ends_with('~')
                && ![".rpmsave", ".rpmorig", ".rpmnew"]
                    .iter()
                    .any(|suffix| name.ends_with(suffix))
        }
        CronieTableKind::UserSpool => parent == Some(Path::new("/var/spool/cron")),
    }
}

#[cfg(unix)]
fn stat_from_metadata(metadata: &std::fs::Metadata) -> CronieFileStat {
    use std::os::unix::fs::MetadataExt;
    CronieFileStat::fixture(
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

fn parse_cronie(
    text: &str,
    kind: CronieTableKind,
    allow_root_marker: bool,
) -> Result<Option<CronieSchedule>, ObservationUnknownReason> {
    // LLM contract: environment directives update the state for subsequent
    // entries only. Each parsed entry snapshots RANDOM_DELAY at its trigger;
    // later directives never rewrite earlier definitions, and no raw command
    // or filesystem/runtime state crosses this pure normalization seam.
    let mut entries = Vec::new();
    let mut timezone = None;
    let mut random_delay = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let suppress_root_logging = allow_root_marker && line.starts_with('-');
        let line = if suppress_root_logging {
            line.strip_prefix('-').expect("checked leading root marker")
        } else {
            line
        };
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            if !key.is_empty() && !key.chars().any(char::is_whitespace) {
                match key {
                    "CRON_TZ" => {
                        let value = trim_cronie_env_value(value)
                            .map_err(|_| ObservationUnknownReason::MalformedSyntax)?;
                        if value.is_empty()
                            || value.len() > 128
                            || value.chars().any(|character| {
                                character.is_control() || character.is_whitespace()
                            })
                        {
                            return Err(ObservationUnknownReason::MalformedSyntax);
                        }
                        if timezone.is_some() {
                            return Err(ObservationUnknownReason::MalformedSyntax);
                        }
                        timezone = Some(crate::report::CronieTimezone::new(value.to_owned()));
                        continue;
                    }
                    "RANDOM_DELAY" => {
                        let value = trim_cronie_env_value(value)
                            .map_err(|_| ObservationUnknownReason::MalformedSyntax)?;
                        let delay = value
                            .parse::<u16>()
                            .map_err(|_| ObservationUnknownReason::MalformedSyntax)?;
                        if delay > 1_440 {
                            return Err(ObservationUnknownReason::MalformedSyntax);
                        }
                        random_delay = Some(delay);
                        continue;
                    }
                    _ => continue,
                }
            }
        }
        let parts = line.split_whitespace().collect::<Vec<_>>();
        let field_count = match kind {
            CronieTableKind::System => 6,
            CronieTableKind::UserSpool => 5,
        };
        if parts.len() <= field_count {
            return Err(ObservationUnknownReason::UnsupportedSyntax);
        }
        let fields = [
            parse_field(parts[0], 0, 59, false)
                .map_err(|_| ObservationUnknownReason::UnsupportedSyntax)?,
            parse_field(parts[1], 0, 23, false)
                .map_err(|_| ObservationUnknownReason::UnsupportedSyntax)?,
            parse_field(parts[2], 1, 31, false)
                .map_err(|_| ObservationUnknownReason::UnsupportedSyntax)?,
            parse_field(parts[3], 1, 12, true)
                .map_err(|_| ObservationUnknownReason::UnsupportedSyntax)?,
            parse_field(parts[4], 0, 7, true)
                .map_err(|_| ObservationUnknownReason::UnsupportedSyntax)?,
        ];
        let user = if kind == CronieTableKind::System {
            let username = parts[5];
            if username.is_empty() || username.len() > 128 || username.chars().any(char::is_control)
            {
                return Err(ObservationUnknownReason::MalformedSyntax);
            }
            if suppress_root_logging && username != "root" {
                return Err(ObservationUnknownReason::UnsupportedSyntax);
            }
            CronieUserField::System
        } else {
            CronieUserField::UserSpool
        };
        let percent_count = parts[field_count..]
            .iter()
            .map(|part| count_unescaped_percent(part))
            .sum::<usize>();
        let percent_count =
            u16::try_from(percent_count).map_err(|_| ObservationUnknownReason::MalformedSyntax)?;
        entries.push(CronieEntry::new(
            fields,
            user,
            CronieCommand::new(percent_count),
            random_delay,
        ));
    }
    if entries.is_empty() {
        Ok(None)
    } else {
        let aggregate_delay = entries.first().and_then(|first| {
            let value = first.random_delay_minutes();
            entries
                .iter()
                .all(|entry| entry.random_delay_minutes() == value)
                .then_some(value)
                .flatten()
        });
        CronieSchedule::new(entries, timezone, aggregate_delay)
            .map(Some)
            .map_err(|_| ObservationUnknownReason::MalformedSyntax)
    }
}

fn trim_cronie_env_value(value: &str) -> Result<&str, ()> {
    let value = value.trim();
    let Some(&first) = value.as_bytes().first() else {
        return Ok(value);
    };
    let is_quote = |byte| matches!(byte, b'\'' | b'"');
    if is_quote(first) {
        if value.len() < 2 || value.as_bytes().last().copied() != Some(first) {
            return Err(());
        }
        return Ok(&value[1..value.len() - 1]);
    }
    if value.as_bytes().last().copied().is_some_and(is_quote) {
        return Err(());
    }
    Ok(value)
}

fn parse_field(token: &str, min: u8, max: u8, names: bool) -> Result<CronieTimeField, ()> {
    if token.is_empty() || token.len() > 128 || token.chars().any(char::is_control) {
        return Err(());
    }
    let mut atoms = Vec::new();
    for item in token.split(',') {
        if item == "*" {
            atoms.push(CronieFieldAtom::Any);
        } else if let Some((lower, upper)) = item.split_once('~') {
            if upper.contains('~') {
                return Err(());
            }
            let lower = parse_optional_number(lower, min, max)?;
            let upper = parse_optional_number(upper, min, max)?;
            if lower.zip(upper).is_some_and(|(lower, upper)| lower > upper) {
                return Err(());
            }
            atoms.push(CronieFieldAtom::Tilde(lower, upper));
        } else if let Some((base, step)) = item.split_once('/') {
            let step = step.parse::<u8>().map_err(|_| ())?;
            if step == 0 {
                return Err(());
            }
            if base == "*" {
                atoms.push(CronieFieldAtom::Step(step));
            } else {
                let (start, end) = if let Some((start, end)) = base.split_once('-') {
                    (
                        parse_value(start, min, max, names)?,
                        parse_value(end, min, max, names)?,
                    )
                } else {
                    (parse_value(base, min, max, names)?, max)
                };
                if start > end {
                    return Err(());
                }
                atoms.push(CronieFieldAtom::Range(start, end, step));
            }
        } else if let Some((start, end)) = item.split_once('-') {
            let start = parse_value(start, min, max, names)?;
            let end = parse_value(end, min, max, names)?;
            if start > end {
                return Err(());
            }
            atoms.push(CronieFieldAtom::Range(start, end, 1));
        } else {
            let value = parse_value(item, min, max, names)?;
            if let Some(name) = parse_named_value(item, min, max, names) {
                atoms.push(CronieFieldAtom::Name(name));
            } else {
                atoms.push(CronieFieldAtom::Value(value));
            }
        }
    }
    CronieTimeField::new(atoms).map_err(|_| ())
}

fn parse_optional_number(value: &str, min: u8, max: u8) -> Result<Option<u8>, ()> {
    if value.is_empty() {
        return Ok(None);
    }
    let value = value.parse::<u8>().map_err(|_| ())?;
    (min..=max)
        .contains(&value)
        .then_some(value)
        .ok_or(())
        .map(Some)
}

fn parse_value(value: &str, min: u8, max: u8, names: bool) -> Result<u8, ()> {
    if let Some(named) = parse_named_value(value, min, max, names) {
        return Ok(named);
    }
    let value = value.parse::<u8>().map_err(|_| ())?;
    (min..=max).contains(&value).then_some(value).ok_or(())
}

fn parse_named_value(value: &str, min: u8, max: u8, names: bool) -> Option<u8> {
    if !names {
        return None;
    }
    let upper = value.to_ascii_uppercase();
    let month_name = matches!(
        upper.as_str(),
        "JAN"
            | "FEB"
            | "MAR"
            | "APR"
            | "MAY"
            | "JUN"
            | "JUL"
            | "AUG"
            | "SEP"
            | "OCT"
            | "NOV"
            | "DEC"
    );
    let weekday_name = matches!(
        upper.as_str(),
        "SUN" | "MON" | "TUE" | "WED" | "THU" | "FRI" | "SAT"
    );
    if (max == 12 && weekday_name) || (max == 7 && month_name) {
        return None;
    }
    let value = match upper.as_str() {
        "JAN" => 1,
        "FEB" => 2,
        "MAR" => 3,
        "APR" => 4,
        "MAY" => 5,
        "JUN" => 6,
        "JUL" => 7,
        "AUG" => 8,
        "SEP" => 9,
        "OCT" => 10,
        "NOV" => 11,
        "DEC" => 12,
        "SUN" => 0,
        "MON" => 1,
        "TUE" => 2,
        "WED" => 3,
        "THU" => 4,
        "FRI" => 5,
        "SAT" => 6,
        _ => return None,
    };
    (min..=max).contains(&value).then_some(value)
}

fn count_unescaped_percent(value: &str) -> usize {
    let mut escaped = false;
    let mut count = 0;
    for byte in value.bytes() {
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'%' {
            count += 1;
        }
    }
    count
}

pub fn evidence_for_table(
    result: &CronieTableResult,
    subject: Subject,
    source_id: SourceRootId,
    ordinal: u32,
    capture: u32,
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
            SourceOccurrenceKey::new(SourceRoot::CronieTable(source_id), ordinal),
            CaptureSequence::new(capture),
        )
    });
    let Some(schedule) = result.schedule().filter(|_| source_key_available) else {
        // LLM contract: Absent, PresentEmpty, Unknown, and Unavailable are
        // evidence-only states. A valid source key is retained as an opaque
        // discriminator for each evidence row, but only Present rows may
        // become inventory candidates. A zero source id/ordinal is also
        // unavailable; no state creates a synthetic definition or repairs it.
        let mut rows = Vec::new();
        for component in [
            ObservationComponent::Configuration,
            ObservationComponent::Schedule,
        ] {
            rows.push(match source_occurrence.as_ref() {
                Some(occurrence) => ProviderEvidence::with_occurrence(
                    Provider::Cronie,
                    subject,
                    component,
                    evidence_presence,
                    occurrence.clone(),
                )?,
                None => {
                    ProviderEvidence::new(Provider::Cronie, subject, component, evidence_presence)?
                }
            });
        }
        for component in [
            ObservationComponent::Runtime,
            ObservationComponent::Activity,
            ObservationComponent::Runs,
            ObservationComponent::LastResult,
        ] {
            let presence = Presence::Unavailable(UnavailableReason::InterfaceUnavailable);
            rows.push(match source_occurrence.as_ref() {
                Some(occurrence) => ProviderEvidence::with_occurrence(
                    Provider::Cronie,
                    subject,
                    component,
                    presence,
                    occurrence.clone(),
                )?,
                None => ProviderEvidence::new(Provider::Cronie, subject, component, presence)?,
            });
        }
        return Ok(rows);
    };

    // LLM contract: one Present table transitions to one normalized
    // occurrence per parsed entry, using deterministic source-local ordinals.
    // Capture remains occurrence evidence; the later inventory seam decides
    // whether to exclude it from logical identity. Account names and command
    // bytes remain redacted, and this pure seam performs no I/O or scheduler action.
    let mut rows = Vec::with_capacity(schedule.entries().len() * 7);
    for (index, entry) in schedule.entries().iter().enumerate() {
        let entry_schedule = CronieSchedule::new(
            vec![entry.clone()],
            schedule.timezone().cloned(),
            entry.random_delay_minutes(),
        )
        .map_err(|_| InputError::InvalidNormalizedValue)?;
        let occurrence = DefinitionOccurrence::new(
            ProviderLogicalKey::Anonymous,
            SourceOccurrenceKey::new(
                SourceRoot::CronieTable(source_id),
                ordinal
                    .checked_add(index as u32)
                    .ok_or(InputError::InvalidNormalizedValue)?,
            ),
            CaptureSequence::new(capture),
        )
        .with_shape(DefinitionShape::Cronie {
            schedule: ShapeState::Known(entry_schedule.clone()),
            principal: ShapeState::Unknown(ShapeUnknownReason::NotObserved),
            command: ShapeState::Unknown(ShapeUnknownReason::NotObserved),
            context: ShapeState::Unknown(ShapeUnknownReason::NotObserved),
        })?;
        for component in [
            ObservationComponent::Configuration,
            ObservationComponent::Schedule,
        ] {
            let row = ProviderEvidence::with_occurrence(
                Provider::Cronie,
                subject,
                component,
                Presence::Present,
                occurrence.clone(),
            )?;
            rows.push(if component == ObservationComponent::Schedule {
                row.with_schedule(Schedule::Cronie(entry_schedule.clone()))?
            } else {
                row
            });
        }
        rows.push(ProviderEvidence::with_occurrence(
            Provider::Cronie,
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
                Provider::Cronie,
                subject,
                component,
                Presence::Unavailable(UnavailableReason::InterfaceUnavailable),
                occurrence.clone(),
            )?);
        }
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat(size: usize) -> CronieFileStat {
        CronieFileStat::fixture(true, 0o400, 0, 1, 1, 2, size as u64, (3, 4))
    }

    #[test]
    fn parses_native_fields_and_keeps_raw_identity_opaque() {
        let text = "CRON_TZ = 'Europe/Tokyo'  \nRANDOM_DELAY = \"7\"\n~ 1-5/2 * JAN-MAR/2 MON-FRI root /bin/echo %secret\n";
        let result = normalize_cronie_file(
            stat(text.len()),
            text.as_bytes(),
            stat(text.len()),
            CronieTableKind::System,
            Some(0),
        );
        let schedule = match result {
            CronieTableResult::Present(value) => value,
            other => panic!("{other:?}"),
        };
        assert_eq!(schedule.entries().len(), 1);
        assert_eq!(schedule.random_delay_minutes(), Some(7));
        assert_eq!(schedule.entries()[0].random_delay_minutes(), Some(7));
        assert!(schedule.timezone().is_some());
        assert_eq!(schedule.entries()[0].command().percent_count(), 1);
        assert!(format!("{schedule:?}").contains("<opaque>"));
        let single_step = b"0/35 0 1 1 * root /bin/true\n";
        let single_step_schedule = match normalize_cronie_file(
            stat(single_step.len()),
            single_step,
            stat(single_step.len()),
            CronieTableKind::System,
            Some(0),
        ) {
            CronieTableResult::Present(value) => value,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            single_step_schedule.entries()[0].fields()[0].atoms(),
            &[CronieFieldAtom::Range(0, 59, 35)]
        );
        let scoped_delay = b"0 0 * * * root /bin/one\nRANDOM_DELAY=60\n0 1 * * * root /bin/two\n";
        let scoped_schedule = match normalize_cronie_file(
            stat(scoped_delay.len()),
            scoped_delay,
            stat(scoped_delay.len()),
            CronieTableKind::System,
            Some(0),
        ) {
            CronieTableResult::Present(value) => value,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            scoped_schedule
                .entries()
                .iter()
                .map(CronieEntry::random_delay_minutes)
                .collect::<Vec<_>>(),
            vec![None, Some(60)]
        );
        assert_eq!(scoped_schedule.random_delay_minutes(), None);
        let scoped_rows = evidence_for_table(
            &CronieTableResult::Present(scoped_schedule.clone()),
            Subject::System,
            SourceRootId::new(2),
            1,
            0,
        )
        .unwrap();
        let observed_delays = scoped_rows
            .iter()
            .filter_map(|row| row.schedule())
            .map(|schedule| match schedule {
                Schedule::Cronie(schedule) => schedule.entries()[0].random_delay_minutes(),
                other => panic!("unexpected schedule: {other:?}"),
            })
            .collect::<Vec<_>>();
        assert_eq!(observed_delays, vec![None, Some(60)]);
        let large_step = b"*/100 0 * * * root /bin/true\n";
        let large_step_schedule = match normalize_cronie_file(
            stat(large_step.len()),
            large_step,
            stat(large_step.len()),
            CronieTableKind::System,
            Some(0),
        ) {
            CronieTableResult::Present(value) => value,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            large_step_schedule.entries()[0].fields()[0].atoms(),
            &[CronieFieldAtom::Step(100)]
        );
        let root_marker = b"-0 0 * * * root /bin/true\n";
        assert!(matches!(
            normalize_cronie_file(
                stat(root_marker.len()),
                root_marker,
                stat(root_marker.len()),
                CronieTableKind::System,
                Some(0)
            ),
            CronieTableResult::Present(_)
        ));
        let user_root_marker = b"-0 0 * * * /bin/true\n";
        assert!(matches!(
            normalize_cronie_file(
                stat(user_root_marker.len()),
                user_root_marker,
                stat(user_root_marker.len()),
                CronieTableKind::UserSpool,
                Some(0)
            ),
            CronieTableResult::Present(_)
        ));
        let non_root_marker = b"-0 0 * * * alice /bin/true\n";
        assert_eq!(
            normalize_cronie_file(
                stat(non_root_marker.len()),
                non_root_marker,
                stat(non_root_marker.len()),
                CronieTableKind::System,
                Some(0)
            ),
            CronieTableResult::Unknown(ObservationUnknownReason::UnsupportedSyntax)
        );
        let rows = evidence_for_table(
            &CronieTableResult::Present(schedule),
            Subject::System,
            SourceRootId::new(1),
            1,
            0,
        )
        .unwrap();
        assert_eq!(rows.len(), 7);
        assert!(rows.iter().any(|row| row.schedule().is_some()));
        assert!(
            rows.iter()
                .filter_map(|row| row.occurrence())
                .all(|occurrence| matches!(
                    occurrence.shape(),
                    Some(DefinitionShape::Cronie {
                        principal: ShapeState::Unknown(ShapeUnknownReason::NotObserved),
                        ..
                    })
                ))
        );
    }

    #[test]
    fn distinguishes_absent_unknown_and_unavailable_states() {
        let empty = normalize_cronie_file(
            stat(10),
            b"# no jobs\n",
            stat(10),
            CronieTableKind::System,
            Some(0),
        );
        assert_eq!(empty, CronieTableResult::PresentEmpty);
        assert_eq!(CronieTableResult::Absent.presence(), Presence::Absent);
        let absent_rows = evidence_for_table(
            &CronieTableResult::Absent,
            Subject::System,
            SourceRootId::new(1),
            2,
            0,
        )
        .unwrap();
        assert!(absent_rows.iter().all(|row| row.occurrence().is_some()));
        let unavailable_rows = evidence_for_table(
            &CronieTableResult::Unavailable(UnavailableReason::PermissionDenied),
            Subject::System,
            SourceRootId::new(1),
            3,
            0,
        )
        .unwrap();
        assert!(
            unavailable_rows
                .iter()
                .all(|row| row.occurrence().is_some())
        );
        let unsupported = normalize_cronie_file(
            stat(12),
            b"@daily true\n",
            stat(12),
            CronieTableKind::UserSpool,
            None,
        );
        assert_eq!(
            unsupported,
            CronieTableResult::Unknown(ObservationUnknownReason::UnsupportedSyntax)
        );
        let missing_newline = b"0 0 * * * root /bin/true";
        assert_eq!(
            normalize_cronie_file(
                stat(missing_newline.len()),
                missing_newline,
                stat(missing_newline.len()),
                CronieTableKind::System,
                Some(0)
            ),
            CronieTableResult::Unknown(ObservationUnknownReason::MalformedSyntax)
        );
        for value in [b"1441".as_slice(), b"99999".as_slice()] {
            let random_delay = [
                b"RANDOM_DELAY=".as_slice(),
                value,
                b"\n0 0 * * * root /bin/true\n".as_slice(),
            ]
            .concat();
            assert_eq!(
                normalize_cronie_file(
                    stat(random_delay.len()),
                    &random_delay,
                    stat(random_delay.len()),
                    CronieTableKind::System,
                    Some(0)
                ),
                CronieTableResult::Unknown(ObservationUnknownReason::MalformedSyntax)
            );
        }

        for text in [
            b"0 0 0 1 * root /bin/true\n".as_slice(),
            b"0 0 1 0 * root /bin/true\n".as_slice(),
        ] {
            assert_eq!(
                normalize_cronie_file(
                    stat(text.len()),
                    text,
                    stat(text.len()),
                    CronieTableKind::System,
                    Some(0)
                ),
                CronieTableResult::Unknown(ObservationUnknownReason::UnsupportedSyntax)
            );
        }
        let duplicate_tz = b"CRON_TZ=UTC\nCRON_TZ=Asia/Tokyo\n0 0 * * * root /bin/true\n";
        assert_eq!(
            normalize_cronie_file(
                stat(duplicate_tz.len()),
                duplicate_tz,
                stat(duplicate_tz.len()),
                CronieTableKind::System,
                Some(0)
            ),
            CronieTableResult::Unknown(ObservationUnknownReason::MalformedSyntax)
        );
        let mismatched_quote = b"CRON_TZ='UTC\"\n0 0 * * * root /bin/true\n";
        assert_eq!(
            normalize_cronie_file(
                stat(mismatched_quote.len()),
                mismatched_quote,
                stat(mismatched_quote.len()),
                CronieTableKind::System,
                Some(0)
            ),
            CronieTableResult::Unknown(ObservationUnknownReason::MalformedSyntax)
        );
        let mut changed = stat(25);
        changed.ino = 99;
        let text = b"0 0 * * * root /bin/true\n";
        assert!(!stat(text.len()).same_generation(changed));
        assert_eq!(
            normalize_cronie_file(
                stat(text.len()),
                text,
                changed,
                CronieTableKind::System,
                Some(0)
            ),
            CronieTableResult::Unavailable(UnavailableReason::ChangedDuringRead)
        );
        assert_eq!(
            normalize_cronie_file(stat(1), &[0xff], stat(1), CronieTableKind::System, Some(0)),
            CronieTableResult::Unavailable(UnavailableReason::UnsupportedEncoding)
        );
        let unsafe_file =
            CronieFileStat::fixture(false, 0o664, 1, 2, 1, 2, text.len() as u64, (3, 4));
        assert_eq!(
            normalize_cronie_file(
                unsafe_file,
                text,
                unsafe_file,
                CronieTableKind::System,
                Some(0)
            ),
            CronieTableResult::Unavailable(UnavailableReason::UnsafeObjectType)
        );
        let executable =
            CronieFileStat::fixture(true, 0o500, 0, 1, 1, 2, text.len() as u64, (3, 4));
        assert_eq!(
            normalize_cronie_file(
                executable,
                text,
                executable,
                CronieTableKind::System,
                Some(0)
            ),
            CronieTableResult::Unavailable(UnavailableReason::UnsafeObjectType)
        );
        let special_mode =
            CronieFileStat::fixture(true, 0o2400, 0, 1, 1, 2, text.len() as u64, (3, 4));
        assert_eq!(
            normalize_cronie_file(
                special_mode,
                text,
                special_mode,
                CronieTableKind::System,
                Some(0)
            ),
            CronieTableResult::Unavailable(UnavailableReason::UnsafeObjectType)
        );
        assert!(!allowed_path(
            Path::new("/etc/cron.d/../passwd"),
            CronieTableKind::System
        ));
        assert!(allowed_path(
            Path::new("/etc/crontab"),
            CronieTableKind::System
        ));
        assert!(allowed_path(
            Path::new("/etc/cron.d/example"),
            CronieTableKind::System
        ));
        assert!(allowed_path(
            Path::new("/var/spool/cron/root"),
            CronieTableKind::UserSpool
        ));
        for ignored in [
            ".hidden",
            "#comment",
            "job~",
            "job.rpmsave",
            "job.rpmorig",
            "job.rpmnew",
        ] {
            assert!(!allowed_path(
                &Path::new("/etc/cron.d").join(ignored),
                CronieTableKind::System
            ));
        }
        for ordinary in ["nix.gc", "job.bak", "job#copy"] {
            assert!(allowed_path(
                &Path::new("/etc/cron.d").join(ordinary),
                CronieTableKind::System
            ));
        }
    }

    #[test]
    fn present_table_keeps_one_occurrence_per_entry() {
        let text = b"* * * * * root /bin/true\n* * * * * root /bin/true\n";
        let result = normalize_cronie_file(
            stat(text.len()),
            text,
            stat(text.len()),
            CronieTableKind::System,
            Some(0),
        );
        let rows =
            evidence_for_table(&result, Subject::System, SourceRootId::new(9), 99, 4).unwrap();
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
        let missing_key =
            evidence_for_table(&result, Subject::System, SourceRootId::new(9), 0, 4).unwrap();
        assert!(missing_key.iter().all(|row| row.occurrence().is_none()));
        assert!(missing_key.iter().take(2).all(|row| {
            row.presence() == Presence::Unavailable(UnavailableReason::MalformedEvidence)
        }));
    }

    #[cfg(unix)]
    #[test]
    fn path_adapter_rejects_links_nonregular_and_over_limit_files() {
        use std::fs;
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join(format!("nix-cronie-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let regular = root.join("regular");
        fs::write(&regular, b"0 0 * * * root /bin/true\n").unwrap();
        let link = root.join("link");
        symlink(&regular, &link).unwrap();
        assert_eq!(
            read_fixture_file(&link, CronieTableKind::System, None),
            CronieTableResult::Unavailable(UnavailableReason::UnsafeObjectType)
        );
        let directory = root.join("directory");
        fs::create_dir(&directory).unwrap();
        assert_eq!(
            read_fixture_file(&directory, CronieTableKind::System, None),
            CronieTableResult::Unavailable(UnavailableReason::UnsafeObjectType)
        );
        let oversized = root.join("oversized");
        fs::write(&oversized, vec![b'x'; MAX_CRONIE_BYTES + 1]).unwrap();
        assert_eq!(
            read_fixture_file(&oversized, CronieTableKind::System, None),
            CronieTableResult::Unavailable(UnavailableReason::ResourceLimitExceeded)
        );
        fs::remove_dir_all(root).unwrap();
    }
}
