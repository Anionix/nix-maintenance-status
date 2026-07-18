use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::anacron_adapter::AnacronDate;
use crate::catalog::{AuthorityResolution, AuthorityRole};
use crate::report::Schedule;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Provider {
    NixDarwinLaunchd,
    NixOsSystemd,
    Cronie,
    Anacron,
    Fcron,
}

impl Provider {
    pub const fn catalog_order(self) -> u8 {
        match self {
            Self::NixDarwinLaunchd => 0,
            Self::NixOsSystemd => 1,
            Self::Cronie => 2,
            Self::Anacron => 3,
            Self::Fcron => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Subject {
    System,
    Uid(u32),
    Unresolved(SubjectOrdinal),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SubjectOrdinal(u32);

impl SubjectOrdinal {
    #[allow(dead_code)] // reserved for the in-crate user-discovery adapter
    pub(crate) const fn new(value: u32) -> Option<Self> {
        if value == 0 { None } else { Some(Self(value)) }
    }
}

impl Subject {
    pub const fn system() -> Self {
        Self::System
    }
    pub const fn uid(uid: u32) -> Self {
        Self::Uid(uid)
    }
    #[allow(dead_code)] // constructed only by the in-crate user-discovery adapter
    pub(crate) const fn unresolved(ordinal: SubjectOrdinal) -> Self {
        Self::Unresolved(ordinal)
    }
    #[allow(dead_code)] // consumed by the later DiagnosticInput constructor
    pub(crate) const fn is_unresolved(self) -> bool {
        matches!(self, Self::Unresolved(_))
    }
    pub fn render(self) -> String {
        match self {
            Self::System => "system".into(),
            Self::Uid(uid) => format!("uid:{uid}"),
            Self::Unresolved(SubjectOrdinal(ordinal)) => {
                format!("subject:unresolved:{ordinal}")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ObservationComponent {
    Discovery,
    Configuration,
    Runtime,
    Schedule,
    Command,
    Activity,
    Runs,
    LastResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum UnavailableReason {
    PermissionDenied,
    InterfaceUnavailable,
    OperationFailed,
    MalformedEvidence,
    UnsupportedEncoding,
    UnsafeObjectType,
    ChangedDuringRead,
    TimedOut,
    ResourceLimitExceeded,
    ConsistencyNotAttested,
    ExternalIdentityMayBeRelevant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Presence {
    Absent,
    PresentEmpty,
    Present,
    Unknown(UnavailableReason),
    Unavailable(UnavailableReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InputError {
    EmptyEvidence,
    DuplicateEvidenceKey,
    InvalidPlatformProvider,
    InvalidScope,
    InvalidScanWindow,
    InvalidSubject,
    InvalidNormalizedValue,
    InvalidDefinitionOccurrence,
    InconsistentInput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TargetPlatform {
    MacOs,
    Linux,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScanScope {
    System,
    CurrentUser,
    Default,
    AllUsers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanWindow {
    start: SystemTime,
    duration: Duration,
}

impl ScanWindow {
    pub fn new(start: SystemTime, duration: Duration) -> Result<Self, InputError> {
        if start.duration_since(UNIX_EPOCH).is_err()
            || duration.is_zero()
            || duration > Duration::from_secs(30)
        {
            return Err(InputError::InvalidScanWindow);
        }
        Ok(Self { start, duration })
    }
    pub fn now(duration: Duration) -> Result<Self, InputError> {
        Self::new(SystemTime::now(), duration)
    }
    pub const fn start(self) -> SystemTime {
        self.start
    }
    pub const fn duration(self) -> Duration {
        self.duration
    }
}

/// Adapter-normalized identifiers reject raw control characters and never
/// expose their text through Debug or a getter.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct NormalizedIdentifier(String);

impl NormalizedIdentifier {
    fn new(value: &str) -> Result<Self, InputError> {
        if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
            return Err(InputError::InvalidNormalizedValue);
        }
        Ok(Self(value.to_owned()))
    }
}

impl fmt::Debug for NormalizedIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<opaque>")
    }
}

macro_rules! normalized_identifier {
    ($name:ident, $visibility:vis) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(NormalizedIdentifier);

        impl $name {
            $visibility fn new(value: &str) -> Result<Self, InputError> {
                Ok(Self(NormalizedIdentifier::new(value)?))
            }
        }
    };
}

normalized_identifier!(LaunchdLabel, pub);
normalized_identifier!(SystemdUnitId, pub);
normalized_identifier!(AnacronStateNamespace, pub);
normalized_identifier!(AnacronJobId, pub);

impl AnacronJobId {
    pub(crate) fn normalized(&self) -> &str {
        &(self.0).0
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceRootId(u32);

impl SourceRootId {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }
}

impl fmt::Debug for SourceRootId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SourceRootId(<opaque>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum LaunchdDomain {
    System,
    User,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum SystemdManagerIdentity {
    System,
    User,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum SourceRoot {
    LaunchdPlist(SourceRootId),
    SystemdUnit(SourceRootId),
    AnacronTable(SourceRootId),
    CronieTable(SourceRootId),
    FcronTable(SourceRootId),
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceOccurrenceKey {
    root: SourceRoot,
    ordinal: u32,
}

impl SourceOccurrenceKey {
    pub const fn new(root: SourceRoot, ordinal: u32) -> Self {
        Self { root, ordinal }
    }
    pub const fn root(&self) -> &SourceRoot {
        &self.root
    }
}

impl fmt::Debug for SourceOccurrenceKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SourceOccurrenceKey(<opaque>)")
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CaptureSequence(u32);

impl CaptureSequence {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }
}

impl fmt::Debug for CaptureSequence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CaptureSequence(<opaque>)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ProviderLogicalKey {
    Launchd {
        domain: LaunchdDomain,
        subject: Subject,
        label: LaunchdLabel,
    },
    Systemd {
        manager: SystemdManagerIdentity,
        subject: Subject,
        canonical_timer_id: SystemdUnitId,
    },
    Anacron {
        state_namespace: AnacronStateNamespace,
        subject: Subject,
        job_id: AnacronJobId,
    },
    Anonymous,
}

/// Identity envelope only. Provider-native schedule, command, and execution
/// shape is added by the provider-specific seams before inventory projection.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DefinitionOccurrence {
    logical_key: ProviderLogicalKey,
    source: SourceOccurrenceKey,
    capture: CaptureSequence,
}

impl DefinitionOccurrence {
    pub fn new(
        logical_key: ProviderLogicalKey,
        source: SourceOccurrenceKey,
        capture: CaptureSequence,
    ) -> Self {
        Self {
            logical_key,
            source,
            capture,
        }
    }

    pub const fn logical_key(&self) -> &ProviderLogicalKey {
        &self.logical_key
    }
    pub const fn source(&self) -> &SourceOccurrenceKey {
        &self.source
    }
    pub const fn capture(&self) -> &CaptureSequence {
        &self.capture
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderEvidence {
    provider: Provider,
    subject: Subject,
    component: ObservationComponent,
    presence: Presence,
    occurrence: Option<DefinitionOccurrence>,
    schedule: Option<Schedule>,
    last_attempt: Option<AnacronDate>,
    authorities: [AuthorityResolution; 3],
}

impl ProviderEvidence {
    pub fn new(
        provider: Provider,
        subject: Subject,
        component: ObservationComponent,
        presence: Presence,
    ) -> Result<Self, InputError> {
        Ok(Self {
            provider,
            subject,
            component,
            presence,
            occurrence: None,
            schedule: None,
            last_attempt: None,
            authorities: [AuthorityResolution::NotClaimed; 3],
        })
    }

    // LLM contract: normalized construction attaches one validated occurrence
    // to any Presence state; provider/source/subject mismatches reject, while
    // component-only rows remain transitional and never become candidates.
    // Unavailable is monotone: missing identity stays Unavailable and no input
    // or sort transition turns it into Absent, Present, or an inferred claim.
    // An unresolved Subject may retain a report-local occurrence, but #44 must
    // not promote it to a cross-report key or candidate AutomationId.
    pub fn with_occurrence(
        provider: Provider,
        subject: Subject,
        component: ObservationComponent,
        presence: Presence,
        occurrence: DefinitionOccurrence,
    ) -> Result<Self, InputError> {
        let identity_matches = matches!(
            (
                provider,
                occurrence.logical_key(),
                occurrence.source().root(),
            ),
            (
                Provider::NixDarwinLaunchd,
                ProviderLogicalKey::Launchd { .. },
                SourceRoot::LaunchdPlist(_),
            ) | (
                Provider::NixOsSystemd,
                ProviderLogicalKey::Systemd { .. },
                SourceRoot::SystemdUnit(_),
            ) | (
                Provider::Anacron,
                ProviderLogicalKey::Anacron { .. },
                SourceRoot::AnacronTable(_),
            ) | (
                Provider::Cronie,
                ProviderLogicalKey::Anonymous,
                SourceRoot::CronieTable(_)
            ) | (
                Provider::Fcron,
                ProviderLogicalKey::Anonymous,
                SourceRoot::FcronTable(_)
            )
        );
        if !identity_matches || !key_subject_matches_domain(occurrence.logical_key(), subject) {
            return Err(InputError::InvalidDefinitionOccurrence);
        }
        Ok(Self {
            provider,
            subject,
            component,
            presence,
            occurrence: Some(occurrence),
            schedule: None,
            last_attempt: None,
            authorities: [AuthorityResolution::NotClaimed; 3],
        })
    }

    pub const fn provider(&self) -> Provider {
        self.provider
    }
    pub const fn subject(&self) -> Subject {
        self.subject
    }
    pub const fn component(&self) -> ObservationComponent {
        self.component
    }
    pub const fn presence(&self) -> Presence {
        self.presence
    }
    pub const fn occurrence(&self) -> Option<&DefinitionOccurrence> {
        self.occurrence.as_ref()
    }
    pub const fn schedule(&self) -> Option<&Schedule> {
        self.schedule.as_ref()
    }
    pub const fn last_attempt(&self) -> Option<AnacronDate> {
        self.last_attempt
    }
    pub const fn authority(&self, role: AuthorityRole) -> AuthorityResolution {
        self.authorities[role.index()]
    }

    // LLM contract: only an in-crate provider adapter may attach one catalog
    // resolution to a normalized row. The requested role must match a
    // Resolved reference; Unresolved/NotApplicable remain explicit, repeated
    // non-empty slots are rejected, and no caller can mint authority or do I/O.
    pub(crate) fn with_authority(
        mut self,
        role: AuthorityRole,
        resolution: AuthorityResolution,
    ) -> Result<Self, InputError> {
        if !matches!(resolution, AuthorityResolution::NotClaimed)
            && !component_accepts_authority(self.component, role)
        {
            return Err(InputError::InvalidNormalizedValue);
        }
        if let AuthorityResolution::Resolved(reference) = resolution
            && (reference.role() != role
                || matches!(reference.scope(), crate::catalog::CatalogScope::Provider(provider) if provider != self.provider))
        {
            return Err(InputError::InvalidNormalizedValue);
        }
        let index = role.index();
        if !matches!(self.authorities[index], AuthorityResolution::NotClaimed) {
            return Err(InputError::DuplicateEvidenceKey);
        }
        if !matches!(resolution, AuthorityResolution::NotClaimed) {
            self.authorities[index] = resolution;
        }
        Ok(self)
    }

    pub(crate) const fn authorities(&self) -> &[AuthorityResolution; 3] {
        &self.authorities
    }
    // LLM contract: this transition is valid only from a Present Schedule row
    // whose provider owns the matching provider-native Schedule variant. A
    // mismatched provider, component, Presence, or repeated attachment is
    // rejected; success stores exactly one normalized schedule and performs no
    // I/O, inference, or fallback. Unknown/Unavailable evidence never becomes
    // a Known schedule.
    pub fn with_schedule(mut self, schedule: Schedule) -> Result<Self, InputError> {
        let provider_matches = matches!(
            (&self.provider, &schedule),
            (Provider::NixDarwinLaunchd, Schedule::Launchd(_))
                | (Provider::NixOsSystemd, Schedule::Systemd(_))
                | (Provider::Anacron, Schedule::Anacron(_))
        );
        if self.component != ObservationComponent::Schedule
            || !provider_matches
            || self.presence != Presence::Present
        {
            return Err(InputError::InvalidNormalizedValue);
        }
        if self.schedule.is_some() {
            return Err(InputError::DuplicateEvidenceKey);
        }
        self.schedule = Some(schedule);
        Ok(self)
    }

    // LLM contract: only an Anacron LastResult row with Unknown/consistency
    // presence may attach one normalized date. Other providers/components and repeated
    // values are rejected; this stores no timestamp path or raw bytes.
    pub(crate) fn with_last_attempt(mut self, date: AnacronDate) -> Result<Self, InputError> {
        if self.provider != Provider::Anacron
            || self.component != ObservationComponent::LastResult
            || !matches!(
                self.presence,
                Presence::Unknown(UnavailableReason::ConsistencyNotAttested)
            )
            || self.last_attempt.is_some()
        {
            return Err(InputError::InvalidNormalizedValue);
        }
        self.last_attempt = Some(date);
        Ok(self)
    }
}

const fn component_accepts_authority(component: ObservationComponent, role: AuthorityRole) -> bool {
    matches!(
        (component, role),
        (
            ObservationComponent::Command,
            AuthorityRole::GcOperationSemantics
        ) | (
            ObservationComponent::Configuration,
            AuthorityRole::AutomationMapping
        ) | (
            ObservationComponent::Runtime,
            AuthorityRole::SchedulerSemantics
        ) | (
            ObservationComponent::Schedule,
            AuthorityRole::SchedulerSemantics
        )
    )
}

fn key_subject_matches_domain(key: &ProviderLogicalKey, subject: Subject) -> bool {
    match key {
        ProviderLogicalKey::Launchd {
            domain,
            subject: key_subject,
            ..
        } => {
            *key_subject == subject
                && match domain {
                    LaunchdDomain::System => subject == Subject::System,
                    LaunchdDomain::User => {
                        matches!(subject, Subject::Uid(_) | Subject::Unresolved(_))
                    }
                }
        }
        ProviderLogicalKey::Systemd {
            manager,
            subject: key_subject,
            ..
        } => {
            *key_subject == subject
                && match manager {
                    SystemdManagerIdentity::System => subject == Subject::System,
                    SystemdManagerIdentity::User => {
                        matches!(subject, Subject::Uid(_) | Subject::Unresolved(_))
                    }
                }
        }
        ProviderLogicalKey::Anacron {
            subject: key_subject,
            ..
        } => *key_subject == subject,
        ProviderLogicalKey::Anonymous => true,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderEvidenceSet(Vec<ProviderEvidence>);

// LLM contract: construction accepts normalized observations, sorts by the
// catalog provider order, preserves distinct typed occurrences and divergent
// values for later conflict handling, and rejects an empty set or a repeated/
// mixed component key; later classifiers never infer.
impl ProviderEvidenceSet {
    pub fn new(mut entries: Vec<ProviderEvidence>) -> Result<Self, InputError> {
        if entries.is_empty() {
            return Err(InputError::EmptyEvidence);
        }
        entries.sort_by_key(|entry| {
            (
                entry.provider.catalog_order(),
                entry.subject,
                entry.component,
                entry.occurrence.clone(),
                entry.presence,
            )
        });
        if entries.windows(2).any(|pair| {
            pair[0].provider == pair[1].provider
                && pair[0].subject == pair[1].subject
                && pair[0].component == pair[1].component
                && match (pair[0].occurrence.as_ref(), pair[1].occurrence.as_ref()) {
                    (Some(left), Some(right)) => {
                        left == right
                            && pair[0].presence == pair[1].presence
                            && pair[0].schedule == pair[1].schedule
                    }
                    _ => true,
                }
        }) {
            return Err(InputError::DuplicateEvidenceKey);
        }
        // LLM contract: one catalogued source slot plus capture can assert one
        // logical key; a second key is malformed input, not multiplicity.
        if entries.iter().enumerate().any(|(index, left)| {
            entries.iter().skip(index + 1).any(|right| {
                left.provider == right.provider
                    && left.subject == right.subject
                    && match (left.occurrence.as_ref(), right.occurrence.as_ref()) {
                        (Some(left), Some(right)) => {
                            left.source() == right.source()
                                && left.capture() == right.capture()
                                && left.logical_key() != right.logical_key()
                        }
                        _ => false,
                    }
            })
        }) {
            return Err(InputError::InconsistentInput);
        }
        Ok(Self(entries))
    }

    pub fn entries(&self) -> &[ProviderEvidence] {
        &self.0
    }
}

// LLM contract: validation is the only trigger that turns normalized rows into
// a DiagnosticInput. It accepts a finite platform-compatible subject set;
// rejects scope/provider/identity/window violations; and never mutates rows or
// infers authority. Unknown external identity is valid only for AllUsers
// Discovery, while Default always retains system plus one concrete UID.
#[allow(dead_code)] // consumed by the later DiagnosticInput constructor
pub(crate) fn validate_input(
    platform: TargetPlatform,
    scope: ScanScope,
    entries: &ProviderEvidenceSet,
) -> Result<(), InputError> {
    let platform_ok = |provider| match platform {
        TargetPlatform::MacOs => provider == Provider::NixDarwinLaunchd,
        TargetPlatform::Linux => matches!(
            provider,
            Provider::NixOsSystemd | Provider::Cronie | Provider::Anacron | Provider::Fcron
        ),
    };
    if entries
        .entries()
        .iter()
        .any(|entry| !platform_ok(entry.provider))
    {
        return Err(InputError::InvalidPlatformProvider);
    }
    let subjects: Vec<_> = entries
        .entries()
        .iter()
        .map(|entry| entry.subject)
        .collect();
    let has_system = subjects.contains(&Subject::System);
    let mut users: Vec<_> = subjects
        .iter()
        .filter_map(|subject| match subject {
            Subject::Uid(uid) => Some(*uid),
            Subject::System | Subject::Unresolved(_) => None,
        })
        .collect();
    users.sort_unstable();
    users.dedup();
    let unresolved_allowed = |entry: &ProviderEvidence| {
        scope == ScanScope::AllUsers
            && entry.component == ObservationComponent::Discovery
            && matches!(entry.subject, Subject::Unresolved(_))
            && entry.presence
                == Presence::Unavailable(UnavailableReason::ExternalIdentityMayBeRelevant)
    };
    if entries.entries().iter().any(|entry| {
        entry.subject.is_unresolved()
            && !unresolved_allowed(entry)
            && !matches!(
                entry.presence,
                Presence::Unavailable(UnavailableReason::ExternalIdentityMayBeRelevant)
            )
    }) {
        return Err(InputError::InvalidSubject);
    }
    if entries.entries().iter().any(|entry| {
        matches!(
            entry.presence,
            Presence::Unavailable(UnavailableReason::ExternalIdentityMayBeRelevant)
        ) && !unresolved_allowed(entry)
    }) {
        return Err(InputError::InvalidScope);
    }
    let valid_scope = match scope {
        ScanScope::System => subjects.iter().all(|subject| *subject == Subject::System),
        ScanScope::CurrentUser => {
            users.len() == 1
                && subjects
                    .iter()
                    .all(|subject| matches!(subject, Subject::Uid(_)))
        }
        ScanScope::Default => has_system && users.len() == 1,
        ScanScope::AllUsers => has_system && !users.is_empty(),
    };
    if valid_scope {
        Ok(())
    } else {
        Err(InputError::InvalidScope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unresolved_identity_is_adapter_owned_and_all_users_only() {
        let unresolved = Subject::unresolved(SubjectOrdinal::new(1).unwrap());
        let rows = ProviderEvidenceSet::new(vec![
            ProviderEvidence::new(
                Provider::NixOsSystemd,
                Subject::System,
                ObservationComponent::Discovery,
                Presence::Present,
            )
            .unwrap(),
            ProviderEvidence::new(
                Provider::NixOsSystemd,
                Subject::Uid(1000),
                ObservationComponent::Discovery,
                Presence::Present,
            )
            .unwrap(),
            ProviderEvidence::new(
                Provider::NixOsSystemd,
                unresolved,
                ObservationComponent::Discovery,
                Presence::Unavailable(UnavailableReason::ExternalIdentityMayBeRelevant),
            )
            .unwrap(),
        ])
        .unwrap();
        assert!(validate_input(TargetPlatform::Linux, ScanScope::AllUsers, &rows).is_ok());
        let ordinary = ProviderEvidenceSet::new(vec![
            ProviderEvidence::new(
                Provider::NixOsSystemd,
                Subject::System,
                ObservationComponent::Discovery,
                Presence::Present,
            )
            .unwrap(),
            ProviderEvidence::new(
                Provider::NixOsSystemd,
                Subject::Uid(1000),
                ObservationComponent::Discovery,
                Presence::Present,
            )
            .unwrap(),
            ProviderEvidence::new(
                Provider::NixOsSystemd,
                unresolved,
                ObservationComponent::Discovery,
                Presence::Present,
            )
            .unwrap(),
        ])
        .unwrap();
        assert_eq!(
            validate_input(TargetPlatform::Linux, ScanScope::AllUsers, &ordinary),
            Err(InputError::InvalidSubject)
        );
    }

    #[test]
    fn provider_and_scope_matrix_is_explicit() {
        let rows = ProviderEvidenceSet::new(vec![
            ProviderEvidence::new(
                Provider::NixOsSystemd,
                Subject::System,
                ObservationComponent::Discovery,
                Presence::Present,
            )
            .unwrap(),
            ProviderEvidence::new(
                Provider::NixOsSystemd,
                Subject::Uid(1000),
                ObservationComponent::Discovery,
                Presence::Present,
            )
            .unwrap(),
        ])
        .unwrap();
        assert!(validate_input(TargetPlatform::Linux, ScanScope::Default, &rows).is_ok());
        assert!(validate_input(TargetPlatform::Linux, ScanScope::AllUsers, &rows).is_ok());
        assert_eq!(
            validate_input(TargetPlatform::MacOs, ScanScope::Default, &rows),
            Err(InputError::InvalidPlatformProvider)
        );
        assert_eq!(
            validate_input(TargetPlatform::Linux, ScanScope::System, &rows),
            Err(InputError::InvalidScope)
        );
        assert!(ScanWindow::new(UNIX_EPOCH, Duration::ZERO).is_err());
        assert!(ScanWindow::new(UNIX_EPOCH, Duration::from_secs(31)).is_err());
    }

    fn launchd_occurrence(label: &str, ordinal: u32, capture: u32) -> DefinitionOccurrence {
        DefinitionOccurrence::new(
            ProviderLogicalKey::Launchd {
                domain: LaunchdDomain::System,
                subject: Subject::System,
                label: LaunchdLabel::new(label).unwrap(),
            },
            SourceOccurrenceKey::new(SourceRoot::LaunchdPlist(SourceRootId::new(1)), ordinal),
            CaptureSequence::new(capture),
        )
    }

    #[test]
    fn definition_occurrences_preserve_multiplicity_without_raw_identity() {
        let first = ProviderEvidence::with_occurrence(
            Provider::NixDarwinLaunchd,
            Subject::System,
            ObservationComponent::Runtime,
            Presence::Present,
            launchd_occurrence("org.nix.gc", 1, 0),
        )
        .unwrap();
        let second = ProviderEvidence::with_occurrence(
            Provider::NixDarwinLaunchd,
            Subject::System,
            ObservationComponent::Runtime,
            Presence::Present,
            launchd_occurrence("org.nix.gc", 2, 1),
        )
        .unwrap();
        let forward = ProviderEvidenceSet::new(vec![first.clone(), second.clone()]).unwrap();
        let reverse = ProviderEvidenceSet::new(vec![second.clone(), first.clone()]).unwrap();
        assert_eq!(forward.entries(), reverse.entries());
        assert!(ProviderEvidenceSet::new(vec![first.clone(), first.clone()]).is_err());
        let conflicting = ProviderEvidence::with_occurrence(
            Provider::NixDarwinLaunchd,
            Subject::System,
            ObservationComponent::Command,
            Presence::Present,
            launchd_occurrence("org.nix.other", 1, 0),
        )
        .unwrap();
        assert!(ProviderEvidenceSet::new(vec![first.clone(), conflicting]).is_err());
        let debug = format!("{:?}", first);
        assert!(debug.contains("<opaque>"));
        assert!(!debug.contains("org.nix.gc"));
        assert!(LaunchdLabel::new("org.nix\ngc").is_err());
        assert!(LaunchdLabel::new("org nix gc").is_ok());
        let occurrence = DefinitionOccurrence::new(
            ProviderLogicalKey::Anonymous,
            SourceOccurrenceKey::new(SourceRoot::CronieTable(SourceRootId::new(2)), 1),
            CaptureSequence::new(0),
        );
        for presence in [
            Presence::Absent,
            Presence::PresentEmpty,
            Presence::Present,
            Presence::Unavailable(UnavailableReason::PermissionDenied),
        ] {
            assert!(
                ProviderEvidence::with_occurrence(
                    Provider::Cronie,
                    Subject::System,
                    ObservationComponent::Command,
                    presence,
                    occurrence.clone(),
                )
                .is_ok()
            );
        }
        assert!(
            ProviderEvidence::with_occurrence(
                Provider::Cronie,
                Subject::Unresolved(SubjectOrdinal::new(1).unwrap()),
                ObservationComponent::Command,
                Presence::Unavailable(UnavailableReason::ExternalIdentityMayBeRelevant),
                occurrence.clone(),
            )
            .is_ok()
        );
        let typed = |presence| {
            ProviderEvidence::with_occurrence(
                Provider::Cronie,
                Subject::System,
                ObservationComponent::Command,
                presence,
                occurrence.clone(),
            )
            .unwrap()
        };
        assert!(
            ProviderEvidenceSet::new(vec![
                typed(Presence::Present),
                typed(Presence::Unavailable(UnavailableReason::PermissionDenied)),
            ])
            .is_ok()
        );
        assert!(
            ProviderEvidenceSet::new(vec![
                typed(Presence::Present),
                typed(Presence::Unavailable(UnavailableReason::PermissionDenied)),
                typed(Presence::Present),
            ])
            .is_err()
        );
        assert!(
            ProviderEvidenceSet::new(vec![typed(Presence::Present), typed(Presence::Present)])
                .is_err()
        );
        assert!(
            ProviderEvidence::with_occurrence(
                Provider::NixDarwinLaunchd,
                Subject::System,
                ObservationComponent::Runtime,
                Presence::Present,
                DefinitionOccurrence::new(
                    ProviderLogicalKey::Launchd {
                        domain: LaunchdDomain::System,
                        subject: Subject::System,
                        label: LaunchdLabel::new("org.nix.gc").unwrap(),
                    },
                    SourceOccurrenceKey::new(SourceRoot::SystemdUnit(SourceRootId::new(3)), 1,),
                    CaptureSequence::new(0),
                ),
            )
            .is_err()
        );
        let absent = ProviderEvidence::new(
            Provider::Cronie,
            Subject::System,
            ObservationComponent::Command,
            Presence::Absent,
        )
        .unwrap();
        let present = ProviderEvidence::new(
            Provider::Cronie,
            Subject::System,
            ObservationComponent::Command,
            Presence::Present,
        )
        .unwrap();
        assert!(ProviderEvidenceSet::new(vec![absent, present]).is_err());
        let legacy = ProviderEvidence::new(
            Provider::NixDarwinLaunchd,
            Subject::System,
            ObservationComponent::Runtime,
            Presence::Present,
        )
        .unwrap();
        assert!(ProviderEvidenceSet::new(vec![legacy, first]).is_err());
    }

    #[test]
    fn normalized_ids_and_provider_scopes_are_explicit() {
        let too_long = "x".repeat(129);
        for value in ["", "bad\nvalue"] {
            assert!(LaunchdLabel::new(value).is_err());
            assert!(SystemdUnitId::new(value).is_err());
            assert!(AnacronStateNamespace::new(value).is_err());
            assert!(AnacronJobId::new(value).is_err());
        }
        assert!(LaunchdLabel::new(&too_long).is_err());
        assert!(SystemdUnitId::new(&too_long).is_err());
        assert!(AnacronStateNamespace::new(&too_long).is_err());
        assert!(AnacronJobId::new(&too_long).is_err());

        let systemd = DefinitionOccurrence::new(
            ProviderLogicalKey::Systemd {
                manager: SystemdManagerIdentity::System,
                subject: Subject::System,
                canonical_timer_id: SystemdUnitId::new("nix-gc.timer").unwrap(),
            },
            SourceOccurrenceKey::new(SourceRoot::SystemdUnit(SourceRootId::new(3)), 1),
            CaptureSequence::new(0),
        );
        assert!(
            ProviderEvidence::with_occurrence(
                Provider::NixOsSystemd,
                Subject::System,
                ObservationComponent::Schedule,
                Presence::Present,
                systemd.clone(),
            )
            .is_ok()
        );
        assert!(
            ProviderEvidence::with_occurrence(
                Provider::NixDarwinLaunchd,
                Subject::System,
                ObservationComponent::Schedule,
                Presence::Present,
                systemd,
            )
            .is_err()
        );

        let anacron = DefinitionOccurrence::new(
            ProviderLogicalKey::Anacron {
                state_namespace: AnacronStateNamespace::new("system").unwrap(),
                subject: Subject::System,
                job_id: AnacronJobId::new("nix-gc").unwrap(),
            },
            SourceOccurrenceKey::new(SourceRoot::AnacronTable(SourceRootId::new(4)), 1),
            CaptureSequence::new(0),
        );
        assert!(
            ProviderEvidence::with_occurrence(
                Provider::Anacron,
                Subject::System,
                ObservationComponent::Schedule,
                Presence::Present,
                anacron,
            )
            .is_ok()
        );
    }
}
