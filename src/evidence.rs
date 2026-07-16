#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
pub enum InputError {
    EmptyEvidence,
    DuplicateEvidenceKey,
    InvalidSubject,
    CardinalityExceeded,
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

// LLM contract: construction accepts normalized observations, sorts by the
// catalog provider order, and rejects an empty set, duplicate key, or
// invalid unresolved identity; no later classifier may reinterpret these rows.
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
