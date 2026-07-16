use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    ExternalIdentityMayBeRelevant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    Absent,
    PresentEmpty,
    Present,
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
    CardinalityExceeded,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderEvidence {
    provider: Provider,
    subject: Subject,
    component: ObservationComponent,
    presence: Presence,
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
        })
    }

    pub const fn provider(self) -> Provider {
        self.provider
    }
    pub const fn subject(self) -> Subject {
        self.subject
    }
    pub const fn component(self) -> ObservationComponent {
        self.component
    }
    pub const fn presence(self) -> Presence {
        self.presence
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderEvidenceSet(Vec<ProviderEvidence>);

// LLM contract: construction accepts normalized observations, sorts by the
// catalog provider order, and rejects an empty set or duplicate key; later
// classifiers must preserve this order and never reinterpret normalized rows.
impl ProviderEvidenceSet {
    pub fn new(mut entries: Vec<ProviderEvidence>) -> Result<Self, InputError> {
        if entries.is_empty() {
            return Err(InputError::EmptyEvidence);
        }
        entries.sort_by_key(|entry| {
            (
                entry.subject,
                entry.provider.catalog_order(),
                entry.component,
            )
        });
        if entries.windows(2).any(|pair| {
            (pair[0].subject, pair[0].provider, pair[0].component)
                == (pair[1].subject, pair[1].provider, pair[1].component)
        }) {
            return Err(InputError::DuplicateEvidenceKey);
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
    if entries.entries().len() > 4096 {
        return Err(InputError::CardinalityExceeded);
    }
    let platform_ok = |provider| match platform {
        TargetPlatform::MacOs => provider == Provider::NixDarwinLaunchd,
        TargetPlatform::Linux => provider != Provider::NixDarwinLaunchd,
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
    if entries
        .entries()
        .iter()
        .any(|entry| entry.subject.is_unresolved() && !unresolved_allowed(entry))
        || entries.entries().iter().any(|entry| {
            matches!(
                entry.presence,
                Presence::Unavailable(UnavailableReason::ExternalIdentityMayBeRelevant)
            ) && !unresolved_allowed(entry)
        })
    {
        return Err(InputError::InvalidSubject);
    }
    match scope {
        ScanScope::System if subjects.iter().any(|subject| *subject != Subject::System) => {
            Err(InputError::InvalidScope)
        }
        ScanScope::CurrentUser
            if users.len() != 1
                || subjects
                    .iter()
                    .any(|subject| !matches!(subject, Subject::Uid(_))) =>
        {
            Err(InputError::InvalidScope)
        }
        ScanScope::Default if !has_system || users.len() != 1 => Err(InputError::InvalidScope),
        ScanScope::AllUsers if !has_system || users.is_empty() => Err(InputError::InvalidScope),
        _ => Ok(()),
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
    fn scope_and_window_boundaries_are_explicit() {
        let system = ProviderEvidenceSet::new(vec![
            ProviderEvidence::new(
                Provider::NixOsSystemd,
                Subject::System,
                ObservationComponent::Discovery,
                Presence::Present,
            )
            .unwrap(),
        ])
        .unwrap();
        assert_eq!(
            validate_input(TargetPlatform::Linux, ScanScope::CurrentUser, &system),
            Err(InputError::InvalidScope)
        );
        assert!(ScanWindow::new(UNIX_EPOCH, Duration::ZERO).is_err());
        assert!(ScanWindow::new(UNIX_EPOCH, Duration::from_secs(31)).is_err());
    }
}
