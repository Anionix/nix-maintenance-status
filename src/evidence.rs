#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TargetPlatform {
    MacOs,
    Linux,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Provider {
    NixDarwinLaunchd,
    NixOsSystemd,
    Cronie,
    Anacron,
    Fcron,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Subject {
    System,
    Uid(u32),
    Unresolved(u32),
}

impl Subject {
    pub const fn system() -> Self {
        Self::System
    }
    pub const fn uid(uid: u32) -> Self {
        Self::Uid(uid)
    }
    pub const fn unresolved(id: u32) -> Self {
        Self::Unresolved(id)
    }

    pub fn render(self) -> String {
        match self {
            Self::System => "system".into(),
            Self::Uid(uid) => format!("uid:{uid}"),
            Self::Unresolved(id) => format!("subject:unresolved:{id}"),
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
pub enum ScanScope {
    System,
    CurrentUser,
    Default,
    AllUsers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InputError {
    InvalidPlatformProvider,
    DuplicateEvidenceKey,
    InvalidSubject,
    CardinalityExceeded,
    InvalidScope,
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
        if subject == Subject::Unresolved(0) {
            return Err(InputError::InvalidSubject);
        }
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

impl ProviderEvidenceSet {
    pub fn new(mut entries: Vec<ProviderEvidence>) -> Result<Self, InputError> {
        if entries.is_empty() || entries.len() > 4096 {
            return Err(InputError::CardinalityExceeded);
        }
        entries.sort_by_key(|entry| (entry.subject, entry.provider, entry.component));
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

/// Validates adapter output before a report classifier consumes it. This seam
/// stores normalized states only; it never stores paths, commands, raw bytes,
/// account metadata, OS errors, telemetry, or authority assertions.
pub fn validate_input(
    platform: TargetPlatform,
    scope: ScanScope,
    entries: &ProviderEvidenceSet,
) -> Result<(), InputError> {
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
    let mut users: Vec<_> = subjects
        .iter()
        .filter_map(|subject| match subject {
            Subject::Uid(uid) => Some(*uid),
            Subject::System | Subject::Unresolved(_) => None,
        })
        .collect();
    users.sort_unstable();
    users.dedup();
    let has_system = subjects.contains(&Subject::System);
    if entries.entries().iter().any(|entry| {
        matches!(
            entry.presence,
            Presence::Unavailable(UnavailableReason::ExternalIdentityMayBeRelevant)
        ) && !(scope == ScanScope::AllUsers
            && entry.component == ObservationComponent::Discovery
            && matches!(entry.subject, Subject::Unresolved(_)))
    }) {
        return Err(InputError::InvalidScope);
    }
    match scope {
        ScanScope::System if subjects.iter().any(|s| *s != Subject::System) => {
            Err(InputError::InvalidScope)
        }
        ScanScope::CurrentUser
            if users.len() != 1 || subjects.iter().any(|s| !matches!(s, Subject::Uid(_))) =>
        {
            Err(InputError::InvalidScope)
        }
        ScanScope::Default
            if !has_system
                || users.len() > 1
                || subjects.iter().any(|s| matches!(s, Subject::Unresolved(_))) =>
        {
            Err(InputError::InvalidScope)
        }
        ScanScope::AllUsers
            if !has_system || subjects.iter().any(|s| matches!(s, Subject::Unresolved(0))) =>
        {
            Err(InputError::InvalidSubject)
        }
        _ => Ok(()),
    }
}
