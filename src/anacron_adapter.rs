use crate::evidence::{
    AnacronJobId, AnacronStateNamespace, CaptureSequence, DefinitionOccurrence, InputError,
    ObservationComponent, ObservationUnknownReason, Presence, Provider, ProviderEvidence,
    ProviderEvidenceSet, ProviderLogicalKey, SourceOccurrenceKey, SourceRoot, SourceRootId,
    Subject, UnavailableReason,
};
use crate::report::{AnacronPeriod, AnacronSchedule, AnacronTimeZone, Schedule};
#[cfg(unix)]
use std::{
    fs::{self, Metadata, OpenOptions},
    io::Read,
    os::unix::{fs::MetadataExt, fs::OpenOptionsExt},
    path::Path,
};

pub const MAX_ANACRON_TABLE_BYTES: usize = 64 * 1024;
pub type AnacronReadError = UnavailableReason;

/// A caller-owned `stat/read/stat` snapshot. `Bounded` is the production seam;
/// `Bytes` is fixture-only. No path, bytes, command, or OS error is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnacronGeneration([u64; 5]);
impl AnacronGeneration {
    pub const fn new(device: u64, inode: u64, size: u64, modified: u64, links: u64) -> Self {
        Self([device, inode, size, modified, links])
    }
    pub fn changed(self, other: Self) -> bool {
        self.0 != other.0
    }
    pub const fn size(self) -> u64 {
        self.0[2]
    }
}

#[cfg(unix)]
enum PathProbeError {
    Missing,
    Failure(AnacronReadError),
}

#[cfg(unix)]
fn io_reason(error: std::io::Error) -> AnacronReadError {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        UnavailableReason::PermissionDenied
    } else {
        UnavailableReason::OperationFailed
    }
}
#[cfg(unix)]
fn generation(metadata: &Metadata) -> AnacronGeneration {
    let modified = (metadata.mtime().max(0) as u64)
        .wrapping_mul(1_000_000_000)
        .wrapping_add(metadata.mtime_nsec().max(0) as u64);
    AnacronGeneration::new(
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        modified,
        metadata.nlink(),
    )
}
#[cfg(unix)]
fn read_bounded_path(
    path: &Path,
) -> Result<(Vec<u8>, AnacronGeneration, AnacronGeneration), PathProbeError> {
    let before_metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            PathProbeError::Missing
        } else {
            PathProbeError::Failure(io_reason(error))
        }
    })?;
    if !before_metadata.file_type().is_file()
        || before_metadata.len() > MAX_ANACRON_TABLE_BYTES as u64
    {
        return Err(PathProbeError::Failure(
            if before_metadata.len() > MAX_ANACRON_TABLE_BYTES as u64 {
                UnavailableReason::ResourceLimitExceeded
            } else {
                UnavailableReason::UnsafeObjectType
            },
        ));
    }
    let before = generation(&before_metadata);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| {
            PathProbeError::Failure(if error.kind() == std::io::ErrorKind::NotFound {
                UnavailableReason::ChangedDuringRead
            } else {
                io_reason(error)
            })
        })?;
    let opened_metadata = file.metadata().map_err(|error| {
        PathProbeError::Failure(if error.kind() == std::io::ErrorKind::NotFound {
            UnavailableReason::ChangedDuringRead
        } else {
            io_reason(error)
        })
    })?;
    let opened = generation(&opened_metadata);
    if !opened_metadata.file_type().is_file() || before.changed(opened) {
        return Err(PathProbeError::Failure(
            UnavailableReason::ChangedDuringRead,
        ));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_ANACRON_TABLE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| PathProbeError::Failure(io_reason(error)))?;
    let after_metadata = file.metadata().map_err(|error| {
        PathProbeError::Failure(if error.kind() == std::io::ErrorKind::NotFound {
            UnavailableReason::ChangedDuringRead
        } else {
            io_reason(error)
        })
    })?;
    let after = generation(&after_metadata);
    if bytes.len() as u64 > MAX_ANACRON_TABLE_BYTES as u64 {
        return Err(PathProbeError::Failure(
            UnavailableReason::ResourceLimitExceeded,
        ));
    }
    if before.changed(after) || after.size() != bytes.len() as u64 {
        return Err(PathProbeError::Failure(
            UnavailableReason::ChangedDuringRead,
        ));
    }
    Ok((bytes, before, after))
}
#[cfg(unix)]
fn allowlisted_table(path: &Path) -> bool {
    path == Path::new("/etc/anacrontab")
}
#[cfg(unix)]
fn allowlisted_timestamp(id: &AnacronJobId, path: &Path) -> bool {
    let mut components = path.components();
    matches!(components.next(), Some(std::path::Component::RootDir))
        && components
            .next()
            .is_some_and(|component| component.as_os_str() == "var")
        && components
            .next()
            .is_some_and(|component| component.as_os_str() == "spool")
        && components
            .next()
            .is_some_and(|component| component.as_os_str() == "anacron")
        && matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none()
        && path.file_name().and_then(|name| name.to_str()) == Some(id.normalized())
}
#[cfg(unix)]
pub fn read_anacron_table(path: &Path) -> AnacronTableProbe<'static> {
    if !allowlisted_table(path) {
        return AnacronTableProbe::failure(UnavailableReason::UnsafeObjectType);
    }
    match read_bounded_path(path) {
        Ok((bytes, before, after)) => AnacronTableProbe(TableProbe::Owned {
            bytes,
            before,
            after,
        }),
        Err(PathProbeError::Missing) => AnacronTableProbe::missing(),
        Err(PathProbeError::Failure(reason)) => AnacronTableProbe::failure(reason),
    }
}
#[cfg(unix)]
pub fn read_anacron_timestamp(id: AnacronJobId, path: &Path) -> AnacronTimestampProbe<'static> {
    if !allowlisted_timestamp(&id, path) {
        return AnacronTimestampProbe::failure(id, UnavailableReason::UnsafeObjectType);
    }
    match read_bounded_path(path) {
        Ok((bytes, before, after)) => AnacronTimestampProbe(TimestampProbe::Owned {
            id,
            bytes,
            before,
            after,
        }),
        Err(PathProbeError::Missing) => AnacronTimestampProbe::missing(id),
        Err(PathProbeError::Failure(reason)) => AnacronTimestampProbe::failure(id, reason),
    }
}

#[derive(Debug)]
#[allow(dead_code)]
enum TableProbe<'a> {
    Missing,
    Borrowed {
        bytes: &'a [u8],
        before: AnacronGeneration,
        after: AnacronGeneration,
    },
    Owned {
        bytes: Vec<u8>,
        before: AnacronGeneration,
        after: AnacronGeneration,
    },
    Failure(AnacronReadError),
}
#[derive(Debug)]
pub struct AnacronTableProbe<'a>(TableProbe<'a>);
impl<'a> AnacronTableProbe<'a> {
    pub const fn missing() -> Self {
        Self(TableProbe::Missing)
    }
    pub const fn failure(reason: AnacronReadError) -> Self {
        Self(TableProbe::Failure(reason))
    }
    #[allow(dead_code)]
    pub(crate) fn fixture(bytes: &'a [u8]) -> Self {
        let generation = AnacronGeneration::new(0, 0, bytes.len() as u64, 0, 1);
        Self(TableProbe::Borrowed {
            bytes,
            before: generation,
            after: generation,
        })
    }
}
#[derive(Debug)]
#[allow(dead_code)]
enum TimestampProbe<'a> {
    Missing(AnacronJobId),
    Borrowed {
        id: AnacronJobId,
        bytes: &'a [u8],
        before: AnacronGeneration,
        after: AnacronGeneration,
    },
    Owned {
        id: AnacronJobId,
        bytes: Vec<u8>,
        before: AnacronGeneration,
        after: AnacronGeneration,
    },
    Failure(AnacronJobId, AnacronReadError),
}
#[derive(Debug)]
pub struct AnacronTimestampProbe<'a>(TimestampProbe<'a>);
impl<'a> AnacronTimestampProbe<'a> {
    pub const fn missing(id: AnacronJobId) -> Self {
        Self(TimestampProbe::Missing(id))
    }
    pub const fn failure(id: AnacronJobId, reason: AnacronReadError) -> Self {
        Self(TimestampProbe::Failure(id, reason))
    }
    #[allow(dead_code)]
    pub(crate) fn fixture(id: AnacronJobId, bytes: &'a [u8]) -> Self {
        let generation = AnacronGeneration::new(0, 0, bytes.len() as u64, 0, 1);
        Self(TimestampProbe::Borrowed {
            id,
            bytes,
            before: generation,
            after: generation,
        })
    }
    fn id(&self) -> &AnacronJobId {
        match &self.0 {
            TimestampProbe::Missing(id) | TimestampProbe::Failure(id, _) => id,
            TimestampProbe::Borrowed { id, .. } | TimestampProbe::Owned { id, .. } => id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AnacronDate {
    year: u16,
    month: u8,
    day: u8,
}
impl AnacronDate {
    pub const fn ymd(self) -> (u16, u8, u8) {
        (self.year, self.month, self.day)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnacronTableState {
    Absent,
    PresentEmpty,
    Present,
    Unknown(ObservationUnknownReason),
    Unavailable(UnavailableReason),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnacronTimestampState {
    Absent,
    Present(AnacronDate),
    Unknown(ObservationUnknownReason),
    Unavailable(UnavailableReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnacronTimestampObservation {
    job_id: AnacronJobId,
    state: AnacronTimestampState,
}
impl AnacronTimestampObservation {
    pub const fn job_id(&self) -> &AnacronJobId {
        &self.job_id
    }
    pub const fn state(&self) -> AnacronTimestampState {
        self.state
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnacronNormalizedObservation {
    table_state: AnacronTableState,
    evidence: ProviderEvidenceSet,
    timestamps: Vec<AnacronTimestampObservation>,
}
impl AnacronNormalizedObservation {
    pub const fn table_state(&self) -> AnacronTableState {
        self.table_state
    }
    pub const fn evidence(&self) -> &ProviderEvidenceSet {
        &self.evidence
    }
    pub fn timestamps(&self) -> &[AnacronTimestampObservation] {
        &self.timestamps
    }
}

struct Job {
    id: AnacronJobId,
    schedule: AnacronSchedule,
}
#[derive(Default)]
struct Context {
    range: Option<(u8, u8)>,
    random_delay: Option<u32>,
}

// LLM contract: Missing -> Absent; bounded valid bytes -> Present/PresentEmpty;
// malformed syntax -> Unknown; read/encoding/object/generation failures ->
// Unavailable. Only schedule/date claims cross this pure seam: runtime,
// activity, results, commands, mappings, raw data, writes, NSS, network,
// telemetry, elevation, locks, and GC execution are never inferred.
pub fn normalize_anacron_snapshot(
    subject: Subject,
    source: SourceRootId,
    capture: CaptureSequence,
    state_namespace: AnacronStateNamespace,
    timezone: AnacronTimeZone,
    table: AnacronTableProbe<'_>,
    timestamps: &[AnacronTimestampProbe<'_>],
) -> Result<AnacronNormalizedObservation, InputError> {
    let (state, jobs) = match table.0 {
        TableProbe::Missing => (AnacronTableState::Absent, Vec::new()),
        TableProbe::Failure(reason) => (AnacronTableState::Unavailable(reason), Vec::new()),
        TableProbe::Borrowed {
            bytes,
            before,
            after,
        } => bounded_table(bytes, before, after, &timezone),
        TableProbe::Owned {
            bytes,
            before,
            after,
        } => bounded_table(&bytes, before, after, &timezone),
    };
    let mut entries = Vec::with_capacity(jobs.len() * 2);
    for (index, job) in jobs.iter().enumerate() {
        let occurrence = DefinitionOccurrence::new(
            ProviderLogicalKey::Anacron {
                state_namespace: state_namespace.clone(),
                subject,
                job_id: job.id.clone(),
            },
            SourceOccurrenceKey::new(SourceRoot::AnacronTable(source), index as u32 + 1),
            capture.clone(),
        );
        let config = ProviderEvidence::with_occurrence(
            Provider::Anacron,
            subject,
            ObservationComponent::Configuration,
            Presence::Present,
            occurrence.clone(),
        )?;
        let schedule = ProviderEvidence::with_occurrence(
            Provider::Anacron,
            subject,
            ObservationComponent::Schedule,
            Presence::Present,
            occurrence.clone(),
        )?
        .with_schedule(Schedule::Anacron(job.schedule.clone()))?;
        entries.extend([config, schedule]);
        let timestamp = timestamp_state(&job.id, timestamps);
        let mut last = ProviderEvidence::with_occurrence(
            Provider::Anacron,
            subject,
            ObservationComponent::LastResult,
            timestamp_presence(timestamp),
            occurrence,
        )?;
        if let AnacronTimestampState::Present(date) = timestamp {
            last = last.with_last_attempt(date)?;
        }
        entries.push(last);
    }
    if entries.is_empty() {
        let presence = match state {
            AnacronTableState::Absent => Presence::Absent,
            AnacronTableState::PresentEmpty => Presence::PresentEmpty,
            AnacronTableState::Present => Presence::Present,
            AnacronTableState::Unknown(reason) => Presence::Unknown(reason),
            AnacronTableState::Unavailable(reason) => Presence::Unavailable(reason),
        };
        entries.push(ProviderEvidence::new(
            Provider::Anacron,
            subject,
            ObservationComponent::Configuration,
            presence,
        )?);
        entries.push(ProviderEvidence::new(
            Provider::Anacron,
            subject,
            ObservationComponent::Schedule,
            presence,
        )?);
    }
    Ok(AnacronNormalizedObservation {
        table_state: state,
        evidence: ProviderEvidenceSet::new(entries)?,
        timestamps: {
            let mut values = timestamps
                .iter()
                .map(normalize_timestamp)
                .collect::<Vec<_>>();
            values.sort_by_key(|value| value.job_id.clone());
            values
        },
    })
}

fn bounded_table(
    bytes: &[u8],
    before: AnacronGeneration,
    after: AnacronGeneration,
    timezone: &AnacronTimeZone,
) -> (AnacronTableState, Vec<Job>) {
    if before.changed(after)
        || before.size() != bytes.len() as u64
        || after.size() != bytes.len() as u64
    {
        return (
            AnacronTableState::Unavailable(UnavailableReason::ChangedDuringRead),
            Vec::new(),
        );
    }
    match parse_table(bytes, timezone) {
        Ok(jobs) if jobs.is_empty() => (AnacronTableState::PresentEmpty, jobs),
        Ok(jobs) => (AnacronTableState::Present, jobs),
        Err(state) => (state, Vec::new()),
    }
}

fn parse_table(bytes: &[u8], timezone: &AnacronTimeZone) -> Result<Vec<Job>, AnacronTableState> {
    if bytes.len() > MAX_ANACRON_TABLE_BYTES {
        return Err(AnacronTableState::Unavailable(
            UnavailableReason::ResourceLimitExceeded,
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| AnacronTableState::Unavailable(UnavailableReason::UnsupportedEncoding))?;
    let mut context = Context::default();
    let mut logical = String::new();
    let mut jobs = Vec::new();
    for raw in text.lines() {
        let line = raw.trim_end();
        let continued = line.strip_suffix('\\');
        logical.push_str(continued.unwrap_or(line));
        if continued.is_some() {
            logical.push(' ');
            continue;
        }
        let line = std::mem::take(&mut logical).trim().to_owned();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.bytes().any(|b| b < 0x20 && b != b'\t') {
            return Err(malformed());
        }
        if let Some((name, value)) = line.split_once('=') {
            let name = name.trim();
            let value = value.trim();
            match name {
                "START_HOURS_RANGE" => {
                    context.range = Some(parse_range(value)?);
                    continue;
                }
                "RANDOM_DELAY" => {
                    context.random_delay = Some(parse_u32(value)?);
                    continue;
                }
                name if is_env_name(name) => {
                    if value.len() > 4096 || value.chars().any(char::is_control) {
                        return Err(malformed());
                    }
                    continue;
                }
                _ => {}
            }
        }
        let mut fields = line.split_whitespace();
        let period = parse_period(fields.next().ok_or(malformed())?)?;
        let delay = parse_u32(fields.next().ok_or(malformed())?)?;
        let raw_id = fields.next().ok_or(malformed())?;
        if raw_id.contains('/') || raw_id.contains('\\') {
            return Err(malformed());
        }
        let id = AnacronJobId::new(raw_id).map_err(|_| malformed())?;
        if fields.next().is_none() {
            return Err(malformed());
        }
        jobs.push(Job {
            id,
            schedule: AnacronSchedule::new(
                period,
                delay,
                context.range,
                context.random_delay,
                timezone.clone(),
            )
            .map_err(|_| malformed())?,
        });
    }
    if !logical.trim().is_empty() {
        return Err(malformed());
    }
    Ok(jobs)
}
const fn malformed() -> AnacronTableState {
    AnacronTableState::Unknown(ObservationUnknownReason::MalformedSyntax)
}
fn parse_period(value: &str) -> Result<AnacronPeriod, AnacronTableState> {
    Ok(match value {
        "daily" | "@daily" => AnacronPeriod::Daily,
        "weekly" | "@weekly" => AnacronPeriod::Weekly,
        "monthly" | "@monthly" => AnacronPeriod::Monthly,
        "yearly" | "@yearly" => AnacronPeriod::Yearly,
        "annually" | "@annually" => AnacronPeriod::Annually,
        value => AnacronPeriod::Days(value.parse().map_err(|_| malformed())?),
    })
}
fn parse_u32(value: &str) -> Result<u32, AnacronTableState> {
    value.trim().parse().map_err(|_| malformed())
}
fn is_env_name(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(c) if c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}
fn parse_range(value: &str) -> Result<(u8, u8), AnacronTableState> {
    let (start, end) = value.trim().split_once('-').ok_or(malformed())?;
    let range = (
        start.parse().map_err(|_| malformed())?,
        end.parse().map_err(|_| malformed())?,
    );
    (range.0 <= 23 && range.1 <= 23 && range.0 <= range.1)
        .then_some(range)
        .ok_or(malformed())
}
fn timestamp_state(
    id: &AnacronJobId,
    probes: &[AnacronTimestampProbe<'_>],
) -> AnacronTimestampState {
    let matches = probes
        .iter()
        .filter(|probe| probe.id() == id)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => AnacronTimestampState::Unavailable(UnavailableReason::InterfaceUnavailable),
        [probe] => normalize_timestamp(probe).state,
        _ => AnacronTimestampState::Unknown(ObservationUnknownReason::MalformedSyntax),
    }
}
fn timestamp_presence(state: AnacronTimestampState) -> Presence {
    match state {
        AnacronTimestampState::Absent => {
            Presence::Unavailable(UnavailableReason::InterfaceUnavailable)
        }
        AnacronTimestampState::Present(_) => {
            Presence::Unavailable(UnavailableReason::ConsistencyNotAttested)
        }
        AnacronTimestampState::Unknown(reason) => Presence::Unknown(reason),
        AnacronTimestampState::Unavailable(reason) => Presence::Unavailable(reason),
    }
}
fn normalize_timestamp(probe: &AnacronTimestampProbe<'_>) -> AnacronTimestampObservation {
    let (job_id, state) = match &probe.0 {
        TimestampProbe::Missing(id) => (id.clone(), AnacronTimestampState::Absent),
        TimestampProbe::Failure(id, reason) => {
            (id.clone(), AnacronTimestampState::Unavailable(*reason))
        }
        TimestampProbe::Borrowed {
            id,
            bytes,
            before,
            after,
        } => (id.clone(), bounded_timestamp(bytes, *before, *after)),
        TimestampProbe::Owned {
            id,
            bytes,
            before,
            after,
        } => (id.clone(), bounded_timestamp(bytes, *before, *after)),
    };
    AnacronTimestampObservation { job_id, state }
}
fn bounded_timestamp(
    bytes: &[u8],
    before: AnacronGeneration,
    after: AnacronGeneration,
) -> AnacronTimestampState {
    if before.changed(after)
        || before.size() != bytes.len() as u64
        || after.size() != bytes.len() as u64
    {
        return AnacronTimestampState::Unavailable(UnavailableReason::ChangedDuringRead);
    }
    match parse_date(bytes) {
        Ok(date) => AnacronTimestampState::Present(date),
        Err(UnavailableReason::UnsupportedEncoding) => {
            AnacronTimestampState::Unavailable(UnavailableReason::UnsupportedEncoding)
        }
        Err(_) => AnacronTimestampState::Unknown(ObservationUnknownReason::MalformedSyntax),
    }
}
fn parse_date(bytes: &[u8]) -> Result<AnacronDate, UnavailableReason> {
    if bytes.len() != 9 || bytes[8] != b'\n' {
        return Err(UnavailableReason::MalformedEvidence);
    }
    let text =
        std::str::from_utf8(&bytes[..8]).map_err(|_| UnavailableReason::UnsupportedEncoding)?;
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(UnavailableReason::MalformedEvidence);
    }
    let year = text[..4]
        .parse()
        .map_err(|_| UnavailableReason::MalformedEvidence)?;
    let month = text[4..6]
        .parse()
        .map_err(|_| UnavailableReason::MalformedEvidence)?;
    let day = text[6..8]
        .parse()
        .map_err(|_| UnavailableReason::MalformedEvidence)?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let max = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => 0,
    };
    ((1970..=9999).contains(&year) && max != 0 && (1..=max).contains(&day))
        .then_some(AnacronDate { year, month, day })
        .ok_or(UnavailableReason::MalformedEvidence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{AuthorityResolution, AuthorityRole};
    fn input(table: AnacronTableProbe<'_>) -> AnacronNormalizedObservation {
        input_with(table, &[])
    }
    fn input_with(
        table: AnacronTableProbe<'_>,
        timestamps: &[AnacronTimestampProbe<'_>],
    ) -> AnacronNormalizedObservation {
        normalize_anacron_snapshot(
            Subject::System,
            SourceRootId::new(1),
            CaptureSequence::new(1),
            AnacronStateNamespace::new("system").unwrap(),
            AnacronTimeZone::system(),
            table,
            timestamps,
        )
        .unwrap()
    }
    #[test]
    fn table_timestamp_and_safety_states_are_typed() {
        let report = input(AnacronTableProbe::fixture(
            b"SHELL = /bin/sh\nPATH = /bin\nMAILFROM = root@example\nNO_MAIL_OUTPUT=yes\nSTART_HOURS_RANGE = 6-22\nRANDOM_DELAY = 15\n@daily 5 nix-gc command=private \\\n /nix/store/gc\n",
        ));
        let Schedule::Anacron(schedule) = report.evidence().entries()[1].schedule().unwrap() else {
            panic!()
        };
        assert_eq!(
            (
                schedule.delay_minutes(),
                schedule.start_hours_range(),
                schedule.random_delay_minutes()
            ),
            (5, Some((6, 22)), Some(15))
        );
        assert!(schedule.catch_up() && !format!("{schedule:?}").contains("private"));
        assert_eq!(
            report.evidence().entries()[0].authority(AuthorityRole::AutomationMapping),
            AuthorityResolution::NotClaimed
        );
        assert_eq!(
            input(AnacronTableProbe::missing()).table_state(),
            AnacronTableState::Absent
        );
        assert_eq!(
            input(AnacronTableProbe::fixture(b"# empty\n")).table_state(),
            AnacronTableState::PresentEmpty
        );
        assert!(matches!(
            input(AnacronTableProbe::fixture(b"daily nope id /bin/true\n")).table_state(),
            AnacronTableState::Unknown(_)
        ));
        assert!(matches!(
            input(AnacronTableProbe::fixture(b"daily 5 x/y /bin/true\n")).table_state(),
            AnacronTableState::Unknown(_)
        ));
        let date = normalize_timestamp(&AnacronTimestampProbe::fixture(
            AnacronJobId::new("x").unwrap(),
            b"20260718\n",
        ));
        assert!(
            matches!(date.state(), AnacronTimestampState::Present(value) if value.ymd() == (2026, 7, 18))
        );
        assert!(matches!(
            normalize_timestamp(&AnacronTimestampProbe::fixture(
                AnacronJobId::new("x").unwrap(),
                b"20260231\n"
            ))
            .state(),
            AnacronTimestampState::Unknown(_)
        ));
        let before = AnacronGeneration::new(1, 2, 3, 4, 1);
        let changed = input(AnacronTableProbe(TableProbe::Borrowed {
            bytes: b"daily 5 x /bin/true\n",
            before,
            after: AnacronGeneration::new(1, 2, 4, 4, 1),
        }));
        assert!(matches!(
            changed.table_state(),
            AnacronTableState::Unavailable(UnavailableReason::ChangedDuringRead)
        ));
        assert!(matches!(
            input(AnacronTableProbe::failure(
                UnavailableReason::UnsafeObjectType
            ))
            .table_state(),
            AnacronTableState::Unavailable(UnavailableReason::UnsafeObjectType)
        ));
        assert!(matches!(
            input(AnacronTableProbe::fixture(&[0xff])).table_state(),
            AnacronTableState::Unavailable(UnavailableReason::UnsupportedEncoding)
        ));
        let bad_timestamp = normalize_timestamp(&AnacronTimestampProbe::fixture(
            AnacronJobId::new("x").unwrap(),
            &[0xff, 0, 0, 0, 0, 0, 0, 0, b'\n'],
        ));
        assert!(matches!(
            bad_timestamp.state(),
            AnacronTimestampState::Unavailable(UnavailableReason::UnsupportedEncoding)
        ));
        let id = AnacronJobId::new("nix-gc").unwrap();
        let timestamp = AnacronTimestampProbe::fixture(id, b"20260718\n");
        let with_timestamp = input_with(
            AnacronTableProbe::fixture(b"daily 5 nix-gc /nix/store/gc\n"),
            &[timestamp],
        );
        let last = with_timestamp
            .evidence()
            .entries()
            .iter()
            .find(|entry| entry.component() == ObservationComponent::LastResult)
            .unwrap();
        assert_eq!(
            last.presence(),
            Presence::Unavailable(UnavailableReason::ConsistencyNotAttested)
        );
        assert_eq!(
            last.last_attempt().map(AnacronDate::ymd),
            Some((2026, 7, 18))
        );
    }

    #[cfg(unix)]
    #[test]
    fn production_paths_are_allowlisted_and_identity_bound() {
        assert!(allowlisted_table(Path::new("/etc/anacrontab")));
        assert!(!allowlisted_table(Path::new("/tmp/anacrontab")));
        let id = AnacronJobId::new("nix-gc").unwrap();
        assert!(allowlisted_timestamp(
            &id,
            Path::new("/var/spool/anacron/nix-gc")
        ));
        assert!(!allowlisted_timestamp(
            &id,
            Path::new("/var/spool/anacron/other")
        ));
        assert!(matches!(
            input(read_anacron_table(Path::new("/tmp/anacrontab"))).table_state(),
            AnacronTableState::Unavailable(UnavailableReason::UnsafeObjectType)
        ));
    }
}
