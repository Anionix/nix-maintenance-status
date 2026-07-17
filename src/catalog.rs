use crate::evidence::Provider;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthorityRole {
    GcOperationSemantics,
    AutomationMapping,
    SchedulerSemantics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum AuthorityUnknownReason {
    IdentityUnavailable,
    IdentityMalformed,
    IdentityNotCatalogued,
    ExactBasisUnverifiable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // Resolved keeps the complete static authority metadata.
pub enum AuthorityResolution {
    Resolved(AuthorityRef),
    Unresolved(AuthorityUnknownReason),
    NotClaimed,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CatalogFamilyId(&'static str);

impl CatalogFamilyId {
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CatalogEntryId(&'static str);

impl CatalogEntryId {
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FullRevision(&'static str);

impl FullRevision {
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourcePin {
    repository: &'static str,
    revision: FullRevision,
}

impl SourcePin {
    pub const fn repository(self) -> &'static str {
        self.repository
    }
    pub const fn revision(self) -> FullRevision {
        self.revision
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContractPin {
    publisher: &'static str,
    revision: FullRevision,
    contract: &'static str,
    build: Option<&'static str>,
    document_digest: Option<&'static str>,
}

impl ContractPin {
    pub const fn publisher(self) -> &'static str {
        self.publisher
    }
    pub const fn revision(self) -> FullRevision {
        self.revision
    }
    pub const fn contract(self) -> &'static str {
        self.contract
    }
    pub const fn build(self) -> Option<&'static str> {
        self.build
    }
    pub const fn document_digest(self) -> Option<&'static str> {
        self.document_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthorityPin {
    Source(SourcePin),
    Contract(ContractPin),
}

/// Adapter-owned identity observation. It can select an embedded Authority,
/// but it cannot create or extend one.
#[derive(Clone, PartialEq, Eq)]
pub struct ObservedAuthorityIdentity(IdentityKind);

#[derive(Clone, PartialEq, Eq)]
enum IdentityKind {
    Source {
        repository: String,
        revision: String,
        fingerprint: Option<NormalizedFingerprint>,
    },
    Contract {
        publisher: String,
        revision: String,
        contract: String,
        build: Option<String>,
        document_digest: Option<String>,
        fingerprint: Option<NormalizedFingerprint>,
    },
}

#[derive(Clone, PartialEq, Eq)]
struct NormalizedFingerprint(String);

impl NormalizedFingerprint {
    fn parse(value: &str) -> Result<Self, CatalogError> {
        if !valid_identity_text(value) {
            return Err(CatalogError::InvalidIdentity);
        }
        Ok(Self(value.to_owned()))
    }
}

impl fmt::Debug for ObservedAuthorityIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self(IdentityKind::Source { .. }) => "source",
            Self(IdentityKind::Contract { .. }) => "contract",
        };
        formatter
            .debug_struct("ObservedAuthorityIdentity")
            .field("kind", &kind)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthorityIdentityObservation {
    Known(ObservedAuthorityIdentity),
    Unavailable,
    Malformed,
}

impl ObservedAuthorityIdentity {
    pub fn source(repository: &str, revision: &str) -> Result<Self, CatalogError> {
        Self::source_with_fingerprint(repository, revision, None)
    }

    pub(crate) fn source_with_fingerprint(
        repository: &str,
        revision: &str,
        fingerprint: Option<&str>,
    ) -> Result<Self, CatalogError> {
        if !valid_identity_text(repository) || !valid_revision_text(revision) {
            return Err(CatalogError::InvalidIdentity);
        }
        let fingerprint = fingerprint.map(NormalizedFingerprint::parse).transpose()?;
        Ok(Self(IdentityKind::Source {
            repository: repository.to_owned(),
            revision: revision.to_owned(),
            fingerprint,
        }))
    }

    pub fn contract(
        publisher: &str,
        revision: &str,
        contract: &str,
        build: Option<&str>,
        document_digest: Option<&str>,
    ) -> Result<Self, CatalogError> {
        Self::contract_with_fingerprint(publisher, revision, contract, build, document_digest, None)
    }

    pub(crate) fn contract_with_fingerprint(
        publisher: &str,
        revision: &str,
        contract: &str,
        build: Option<&str>,
        document_digest: Option<&str>,
        fingerprint: Option<&str>,
    ) -> Result<Self, CatalogError> {
        if !valid_identity_text(publisher)
            || !valid_revision_text(revision)
            || !valid_identity_text(contract)
            || build.is_some_and(|value| !valid_identity_text(value))
            || document_digest.is_some_and(|value| !valid_digest(value))
        {
            return Err(CatalogError::InvalidIdentity);
        }
        let fingerprint = fingerprint.map(NormalizedFingerprint::parse).transpose()?;
        Ok(Self(IdentityKind::Contract {
            publisher: publisher.to_owned(),
            revision: revision.to_owned(),
            contract: contract.to_owned(),
            build: build.map(str::to_owned),
            document_digest: document_digest.map(str::to_owned),
            fingerprint,
        }))
    }
}

impl AuthorityPin {
    fn matches(&self, identity: &ObservedAuthorityIdentity) -> bool {
        match (self, &identity.0) {
            (
                Self::Source(pin),
                IdentityKind::Source {
                    repository,
                    revision,
                    ..
                },
            ) => pin.repository == repository && pin.revision.0 == revision,
            (
                Self::Contract(pin),
                IdentityKind::Contract {
                    publisher,
                    revision,
                    contract,
                    build,
                    document_digest,
                    ..
                },
            ) => {
                pin.publisher == publisher
                    && pin.revision.0 == revision
                    && pin.contract == contract
                    && pin.build == build.as_deref()
                    && pin.document_digest == document_digest.as_deref()
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceCitation {
    title: &'static str,
    url: &'static str,
}

impl SourceCitation {
    pub const fn title(self) -> &'static str {
        self.title
    }
    pub const fn url(self) -> &'static str {
        self.url
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IntegrityPin {
    label: &'static str,
    digest: &'static str,
}

impl IntegrityPin {
    pub const fn label(self) -> &'static str {
        self.label
    }
    pub const fn digest(self) -> &'static str {
        self.digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum LifecycleState {
    Active,
    Deprecated,
    Tombstoned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Lifecycle {
    state: LifecycleState,
    first_audited_on: &'static str,
    last_audited_on: &'static str,
    transitioned_on: Option<&'static str>,
    reason: Option<&'static str>,
    replacement: Option<CatalogEntryId>,
}

impl Lifecycle {
    pub const fn state(self) -> LifecycleState {
        self.state
    }
    pub const fn first_audited_on(self) -> &'static str {
        self.first_audited_on
    }
    pub const fn last_audited_on(self) -> &'static str {
        self.last_audited_on
    }
    pub const fn transitioned_on(self) -> Option<&'static str> {
        self.transitioned_on
    }
    pub const fn reason(self) -> Option<&'static str> {
        self.reason
    }
    pub const fn replacement(self) -> Option<CatalogEntryId> {
        self.replacement
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CatalogScope {
    Nix,
    Provider(Provider),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthorityRef {
    entry_id: CatalogEntryId,
    family_id: CatalogFamilyId,
    scope: CatalogScope,
    role: AuthorityRole,
    pin: AuthorityPin,
    fingerprint: Option<&'static str>,
    citations: &'static [SourceCitation],
    integrity: &'static [IntegrityPin],
    lifecycle: Lifecycle,
}

impl AuthorityRef {
    pub const fn entry_id(self) -> CatalogEntryId {
        self.entry_id
    }
    pub const fn family_id(self) -> CatalogFamilyId {
        self.family_id
    }
    pub const fn scope(self) -> CatalogScope {
        self.scope
    }
    pub const fn role(self) -> AuthorityRole {
        self.role
    }
    pub const fn pin(self) -> AuthorityPin {
        self.pin
    }
    pub const fn fingerprint(self) -> Option<&'static str> {
        self.fingerprint
    }
    pub const fn citations(self) -> &'static [SourceCitation] {
        self.citations
    }
    pub const fn integrity(self) -> &'static [IntegrityPin] {
        self.integrity
    }
    pub const fn lifecycle(self) -> Lifecycle {
        self.lifecycle
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CatalogError {
    EmptyIdentifier,
    InvalidIdentity,
    InvalidRevision,
    InvalidDate,
    InvalidCitation,
    InvalidFingerprint,
    InvalidLifecycle,
    DuplicateIdentity,
    InvalidRoleScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderCatalog;

impl ProviderCatalog {
    pub const fn embedded() -> Self {
        Self
    }

    pub fn entries(self) -> &'static [AuthorityRef] {
        &CATALOG
    }

    pub fn check(self) -> Result<(), CatalogError> {
        validate_catalog(self.entries())
    }

    #[allow(dead_code)] // consumed by the report classifier child after this catalog slice.
    pub(crate) fn resolve(
        self,
        role: AuthorityRole,
        scope: CatalogScope,
        identity: &ObservedAuthorityIdentity,
    ) -> AuthorityResolution {
        resolve_entries(self.entries(), role, scope, identity)
    }
}

fn resolve_entries(
    entries: &[AuthorityRef],
    role: AuthorityRole,
    scope: CatalogScope,
    identity: &ObservedAuthorityIdentity,
) -> AuthorityResolution {
    let Some(entry) = entries
        .iter()
        .find(|entry| entry.role == role && entry.scope == scope && entry.pin.matches(identity))
    else {
        return AuthorityResolution::Unresolved(AuthorityUnknownReason::IdentityNotCatalogued);
    };
    if entry.fingerprint != observed_fingerprint(identity) {
        return AuthorityResolution::Unresolved(AuthorityUnknownReason::ExactBasisUnverifiable);
    }
    match entry.lifecycle.state {
        LifecycleState::Active | LifecycleState::Deprecated => {
            AuthorityResolution::Resolved(*entry)
        }
        LifecycleState::Tombstoned => {
            AuthorityResolution::Unresolved(AuthorityUnknownReason::ExactBasisUnverifiable)
        }
    }
}

impl ProviderCatalog {
    #[allow(dead_code)] // consumed by the report classifier child after this catalog slice.
    pub(crate) fn resolve_observation(
        self,
        role: AuthorityRole,
        scope: CatalogScope,
        observation: &AuthorityIdentityObservation,
    ) -> AuthorityResolution {
        match observation {
            AuthorityIdentityObservation::Known(identity) => self.resolve(role, scope, identity),
            AuthorityIdentityObservation::Unavailable => {
                AuthorityResolution::Unresolved(AuthorityUnknownReason::IdentityUnavailable)
            }
            AuthorityIdentityObservation::Malformed => {
                AuthorityResolution::Unresolved(AuthorityUnknownReason::IdentityMalformed)
            }
        }
    }
}

fn observed_fingerprint(identity: &ObservedAuthorityIdentity) -> Option<&str> {
    match &identity.0 {
        IdentityKind::Source { fingerprint, .. } | IdentityKind::Contract { fingerprint, .. } => {
            fingerprint
                .as_ref()
                .map(|fingerprint| fingerprint.0.as_str())
        }
    }
}

pub const fn embedded_catalog() -> ProviderCatalog {
    ProviderCatalog::embedded()
}

pub fn catalog_check() -> Result<(), CatalogError> {
    embedded_catalog().check()
}

// LLM contract: `resolve` is the only Authority transition trigger. A matching
// exact identity plus normalized fingerprint resolves an Active/Deprecated entry;
// a tombstone or incomplete fingerprint is Unresolved(ExactBasisUnverifiable),
// and a catalog miss is Unresolved(IdentityNotCatalogued). Family IDs never
// resolve alone, and lookup never mutates Evidence/Coverage. No runtime network,
// I/O, telemetry, mutation, elevation, scheduler, or GC execution occurs.
fn validate_catalog(entries: &[AuthorityRef]) -> Result<(), CatalogError> {
    for entry in entries {
        if !valid_identity_text(entry.entry_id.0) || !valid_identity_text(entry.family_id.0) {
            return Err(CatalogError::EmptyIdentifier);
        }
        match entry.pin {
            AuthorityPin::Source(pin) => {
                if !valid_identity_text(pin.repository) {
                    return Err(CatalogError::InvalidIdentity);
                }
            }
            AuthorityPin::Contract(pin) => {
                if !valid_identity_text(pin.publisher)
                    || !valid_identity_text(pin.contract)
                    || pin.build.is_some_and(|build| !valid_identity_text(build))
                    || pin
                        .document_digest
                        .is_some_and(|digest| !valid_digest(digest))
                {
                    return Err(CatalogError::InvalidIdentity);
                }
            }
        }
        if !valid_revision(entry.pin) {
            return Err(CatalogError::InvalidRevision);
        }
        if (entry.lifecycle.state != LifecycleState::Tombstoned && entry.fingerprint.is_none())
            || entry
                .fingerprint
                .is_some_and(|fingerprint| !valid_identity_text(fingerprint))
        {
            return Err(CatalogError::InvalidFingerprint);
        }
        if entry.citations.is_empty()
            || entry.citations.iter().any(|citation| {
                !valid_text(citation.title)
                    || citation.url.is_empty()
                    || !valid_citation_url(citation.url)
                    || citation_revision(citation.url) != Some(pin_revision(entry.pin))
                    || !citation_owner_matches(citation.url, entry.pin)
            })
        {
            return Err(CatalogError::InvalidCitation);
        }
        if !valid_date(entry.lifecycle.first_audited_on)
            || !valid_date(entry.lifecycle.last_audited_on)
            || entry.lifecycle.first_audited_on > entry.lifecycle.last_audited_on
        {
            return Err(CatalogError::InvalidDate);
        }
        if entry.lifecycle.state != LifecycleState::Active && entry.lifecycle.reason.is_none() {
            return Err(CatalogError::InvalidLifecycle);
        }
        if entry.lifecycle.state != LifecycleState::Tombstoned
            && entry.lifecycle.replacement.is_some()
        {
            return Err(CatalogError::InvalidLifecycle);
        }
        if entry.lifecycle.state == LifecycleState::Active
            && (entry.lifecycle.transitioned_on.is_some()
                || entry.lifecycle.reason.is_some()
                || entry.lifecycle.replacement.is_some())
        {
            return Err(CatalogError::InvalidLifecycle);
        }
        if entry.lifecycle.state != LifecycleState::Active
            && (entry.lifecycle.transitioned_on.is_none()
                || !valid_date(entry.lifecycle.transitioned_on.unwrap())
                || entry.lifecycle.reason.is_none())
        {
            return Err(CatalogError::InvalidLifecycle);
        }
        if entry
            .lifecycle
            .reason
            .is_some_and(|reason| !valid_text(reason))
            || entry.lifecycle.transitioned_on.is_some_and(|transitioned| {
                transitioned < entry.lifecycle.first_audited_on
                    || transitioned > entry.lifecycle.last_audited_on
            })
        {
            return Err(CatalogError::InvalidLifecycle);
        }
        let valid_scope = matches!(
            (entry.role, entry.scope, entry.pin),
            (
                AuthorityRole::GcOperationSemantics,
                CatalogScope::Nix,
                AuthorityPin::Source(_)
            ) | (
                AuthorityRole::AutomationMapping,
                CatalogScope::Provider(Provider::NixDarwinLaunchd | Provider::NixOsSystemd),
                AuthorityPin::Source(_)
            ) | (
                AuthorityRole::SchedulerSemantics,
                CatalogScope::Provider(_),
                AuthorityPin::Contract(_)
            )
        );
        if !valid_scope {
            return Err(CatalogError::InvalidRoleScope);
        }
        if entry
            .integrity
            .iter()
            .any(|pin| !valid_text(pin.label) || !valid_text(pin.digest))
        {
            return Err(CatalogError::InvalidIdentity);
        }
        if entry.lifecycle.replacement.is_some_and(|replacement| {
            replacement == entry.entry_id
                || !entries
                    .iter()
                    .any(|candidate| candidate.entry_id == replacement)
        }) {
            return Err(CatalogError::InvalidLifecycle);
        }
        if entries.iter().any(|other| {
            !std::ptr::eq(other, entry)
                && (other.entry_id == entry.entry_id
                    || (other.family_id == entry.family_id
                        && (other.role != entry.role
                            || other.scope != entry.scope
                            || other.fingerprint != entry.fingerprint))
                    || (other.role == entry.role
                        && other.scope == entry.scope
                        && same_pin_identity(other.pin, entry.pin)))
        }) {
            return Err(CatalogError::DuplicateIdentity);
        }
    }
    Ok(())
}

fn same_pin_identity(left: AuthorityPin, right: AuthorityPin) -> bool {
    match (left, right) {
        (AuthorityPin::Source(left), AuthorityPin::Source(right)) => {
            left.repository == right.repository && left.revision == right.revision
        }
        (AuthorityPin::Contract(left), AuthorityPin::Contract(right)) => left == right,
        _ => false,
    }
}

fn valid_revision(pin: AuthorityPin) -> bool {
    valid_revision_text(pin_revision(pin))
}

fn pin_revision(pin: AuthorityPin) -> &'static str {
    match pin {
        AuthorityPin::Source(pin) => pin.revision.0,
        AuthorityPin::Contract(pin) => pin.revision.0,
    }
}

fn valid_revision_text(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn valid_identity_text(value: &str) -> bool {
    valid_text(value)
        && !value.starts_with('/')
        && !value.contains("..")
        && !value.chars().any(char::is_whitespace)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_citation_url(value: &str) -> bool {
    let Some(revision) = value.split("/blob/").nth(1).and_then(|rest| rest.get(..40)) else {
        return false;
    };
    valid_text(value)
        && value.starts_with("https://github.com/")
        && valid_revision_text(revision)
        && value
            .split("/blob/")
            .nth(1)
            .is_some_and(|rest| rest.len() > 41 && rest.as_bytes()[40] == b'/')
}

fn citation_revision(value: &str) -> Option<&str> {
    value.split("/blob/").nth(1).and_then(|rest| rest.get(..40))
}

fn citation_owner_matches(value: &str, pin: AuthorityPin) -> bool {
    let Some(repository) = value
        .strip_prefix("https://github.com/")
        .and_then(|value| value.split("/blob/").next())
    else {
        return false;
    };
    match pin {
        AuthorityPin::Source(pin) => repository == pin.repository,
        AuthorityPin::Contract(pin) => match pin.publisher {
            "Apple" => repository == "apple-oss-distributions/launchd",
            "systemd" => repository == "systemd/systemd",
            "cronie-crond" => repository == "cronie-crond/cronie",
            "yo8192/fcron" => repository == "yo8192/fcron",
            _ => false,
        },
    }
}

fn valid_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
    {
        return false;
    }
    let month = value[5..7].parse::<u8>().unwrap_or(0);
    let day = value[8..10].parse::<u8>().unwrap_or(0);
    let year = value[0..4].parse::<u16>().unwrap_or(0);
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 400 == 0 || (year % 4 == 0 && year % 100 != 0) => 29,
        2 => 28,
        _ => 0,
    };
    year > 0 && day >= 1 && day <= max_day
}

#[allow(clippy::too_many_arguments)]
const fn source(
    entry_id: &'static str,
    family_id: &'static str,
    scope: CatalogScope,
    role: AuthorityRole,
    repository: &'static str,
    revision: &'static str,
    fingerprint: Option<&'static str>,
    citations: &'static [SourceCitation],
) -> AuthorityRef {
    AuthorityRef {
        entry_id: CatalogEntryId(entry_id),
        family_id: CatalogFamilyId(family_id),
        scope,
        role,
        pin: AuthorityPin::Source(SourcePin {
            repository,
            revision: FullRevision(revision),
        }),
        fingerprint,
        citations,
        integrity: &[],
        lifecycle: Lifecycle {
            state: LifecycleState::Active,
            first_audited_on: "2026-07-17",
            last_audited_on: "2026-07-17",
            transitioned_on: None,
            reason: None,
            replacement: None,
        },
    }
}

#[allow(clippy::too_many_arguments)]
const fn contract(
    entry_id: &'static str,
    family_id: &'static str,
    scope: CatalogScope,
    role: AuthorityRole,
    publisher: &'static str,
    revision: &'static str,
    contract_name: &'static str,
    build: Option<&'static str>,
    digest: Option<&'static str>,
    fingerprint: Option<&'static str>,
    citations: &'static [SourceCitation],
) -> AuthorityRef {
    AuthorityRef {
        entry_id: CatalogEntryId(entry_id),
        family_id: CatalogFamilyId(family_id),
        scope,
        role,
        pin: AuthorityPin::Contract(ContractPin {
            publisher,
            revision: FullRevision(revision),
            contract: contract_name,
            build,
            document_digest: digest,
        }),
        fingerprint,
        citations,
        integrity: &[],
        lifecycle: Lifecycle {
            state: LifecycleState::Active,
            first_audited_on: "2026-07-17",
            last_audited_on: "2026-07-17",
            transitioned_on: None,
            reason: None,
            replacement: None,
        },
    }
}

const NIX_CITATIONS: &[SourceCitation] = &[
    SourceCitation {
        title: "Nix garbage collection implementation",
        url: "https://github.com/NixOS/nix/blob/035f34f13f969cf72ca4ea60369d907972402956/src/nix/nix-collect-garbage/nix-collect-garbage.cc",
    },
    SourceCitation {
        title: "Nix store garbage collection implementation",
        url: "https://github.com/NixOS/nix/blob/035f34f13f969cf72ca4ea60369d907972402956/src/nix/store-gc.cc",
    },
];
const DARWIN_CITATIONS: &[SourceCitation] = &[
    SourceCitation {
        title: "nix-darwin nix-gc module",
        url: "https://github.com/nix-darwin/nix-darwin/blob/8c62fba0854ba15c8917aed18894dbccb48a3777/modules/services/nix-gc/default.nix",
    },
    SourceCitation {
        title: "nix-darwin launchd generation",
        url: "https://github.com/nix-darwin/nix-darwin/blob/8c62fba0854ba15c8917aed18894dbccb48a3777/modules/launchd/default.nix",
    },
];
const LAUNCHD_CITATIONS: &[SourceCitation] = &[SourceCitation {
    title: "Apple launchd plist contract",
    url: "https://github.com/apple-oss-distributions/launchd/blob/d448a1c8f70a61202f8705f94337f686b87c30c4/man/launchd.plist.5",
}];
const NIXOS_CITATIONS: &[SourceCitation] = &[
    SourceCitation {
        title: "NixOS nix-gc module",
        url: "https://github.com/NixOS/nixpkgs/blob/e8d924d50a462f89166e31a27bdcbbade35fd8e6/nixos/modules/services/misc/nix-gc.nix",
    },
    SourceCitation {
        title: "NixOS systemd unit generation",
        url: "https://github.com/NixOS/nixpkgs/blob/e8d924d50a462f89166e31a27bdcbbade35fd8e6/nixos/lib/systemd-lib.nix",
    },
];
const SYSTEMD_CITATIONS: &[SourceCitation] = &[
    SourceCitation {
        title: "systemd timer contract",
        url: "https://github.com/systemd/systemd/blob/de9dbc37ad4aa637e200ac02a0545095997055df/man/systemd.timer.xml",
    },
    SourceCitation {
        title: "systemd calendar contract",
        url: "https://github.com/systemd/systemd/blob/de9dbc37ad4aa637e200ac02a0545095997055df/man/systemd.time.xml",
    },
];
const SYSTEMD_262_CITATIONS: &[SourceCitation] = &[
    SourceCitation {
        title: "systemd timer contract",
        url: "https://github.com/systemd/systemd/blob/07a9d1f929f7ae2c4d4fbbdb0d307d993e83be8e/man/systemd.timer.xml",
    },
    SourceCitation {
        title: "systemd calendar contract",
        url: "https://github.com/systemd/systemd/blob/07a9d1f929f7ae2c4d4fbbdb0d307d993e83be8e/man/systemd.time.xml",
    },
];
const CRONIE_CITATIONS: &[SourceCitation] = &[SourceCitation {
    title: "Cronie table contract",
    url: "https://github.com/cronie-crond/cronie/blob/5f9f16b5663becefdd0dd70df31c0ef5ac36f943/man/crontab.5",
}];
const ANACRON_CITATIONS: &[SourceCitation] = &[SourceCitation {
    title: "anacron runtime contract",
    url: "https://github.com/cronie-crond/cronie/blob/5f9f16b5663becefdd0dd70df31c0ef5ac36f943/man/anacron.8",
}];
const FCRON_CITATIONS: &[SourceCitation] = &[
    SourceCitation {
        title: "fcron schedule contract",
        url: "https://github.com/yo8192/fcron/blob/8198d4b90690fb0f53cca931b6e9bb6d4b9e6f83/doc/en/fcrontab.5.sgml",
    },
    SourceCitation {
        title: "fcron daemon contract",
        url: "https://github.com/yo8192/fcron/blob/8198d4b90690fb0f53cca931b6e9bb6d4b9e6f83/doc/en/fcron.8.sgml",
    },
];
const FCRON_341_CITATIONS: &[SourceCitation] = &[
    SourceCitation {
        title: "fcron schedule contract",
        url: "https://github.com/yo8192/fcron/blob/a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130/doc/en/fcrontab.5.sgml",
    },
    SourceCitation {
        title: "fcron daemon contract",
        url: "https://github.com/yo8192/fcron/blob/a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130/doc/en/fcron.8.sgml",
    },
];

const CATALOG: [AuthorityRef; 10] = [
    source(
        "nix.gc.operation.v1",
        "nix.gc.operation.v1",
        CatalogScope::Nix,
        AuthorityRole::GcOperationSemantics,
        "NixOS/nix",
        "035f34f13f969cf72ca4ea60369d907972402956",
        Some("nix-gc-operation-v1"),
        NIX_CITATIONS,
    ),
    source(
        "nix-darwin.gc.mapping.v1",
        "nix-darwin.gc.mapping.v1",
        CatalogScope::Provider(Provider::NixDarwinLaunchd),
        AuthorityRole::AutomationMapping,
        "nix-darwin/nix-darwin",
        "8c62fba0854ba15c8917aed18894dbccb48a3777",
        Some("nix-darwin-gc-launchd-mapping-v1"),
        DARWIN_CITATIONS,
    ),
    source(
        "nixos.gc.mapping.v1",
        "nixos.gc.mapping.v1",
        CatalogScope::Provider(Provider::NixOsSystemd),
        AuthorityRole::AutomationMapping,
        "NixOS/nixpkgs",
        "e8d924d50a462f89166e31a27bdcbbade35fd8e6",
        Some("nixos-gc-systemd-mapping-v1"),
        NIXOS_CITATIONS,
    ),
    contract(
        "launchd.macos-27.scheduler.v1",
        "launchd.macos-27.scheduler.v1",
        CatalogScope::Provider(Provider::NixDarwinLaunchd),
        AuthorityRole::SchedulerSemantics,
        "Apple",
        "d448a1c8f70a61202f8705f94337f686b87c30c4",
        "launchd.plist.5",
        Some("26A5378j"),
        Some("1c5f5041c1d3492988bfa6f9dc6d969dfd072d20af2703c28d9a8f6ed6aaadcb"),
        Some("launchd-macos-27-v1"),
        LAUNCHD_CITATIONS,
    ),
    contract(
        "systemd.v261.scheduler.v1",
        "systemd.v261.scheduler.v1",
        CatalogScope::Provider(Provider::NixOsSystemd),
        AuthorityRole::SchedulerSemantics,
        "systemd",
        "de9dbc37ad4aa637e200ac02a0545095997055df",
        "systemd.timer.xml",
        Some("261"),
        None,
        Some("systemd-v261-v1"),
        SYSTEMD_CITATIONS,
    ),
    contract(
        "systemd.v262-devel.scheduler.v1",
        "systemd.v262-devel.scheduler.v1",
        CatalogScope::Provider(Provider::NixOsSystemd),
        AuthorityRole::SchedulerSemantics,
        "systemd",
        "07a9d1f929f7ae2c4d4fbbdb0d307d993e83be8e",
        "systemd.timer.xml",
        Some("262~devel"),
        None,
        Some("systemd-v262-devel-v1"),
        SYSTEMD_262_CITATIONS,
    ),
    contract(
        "cronie.v1.scheduler.v1",
        "cronie.v1.scheduler.v1",
        CatalogScope::Provider(Provider::Cronie),
        AuthorityRole::SchedulerSemantics,
        "cronie-crond",
        "5f9f16b5663becefdd0dd70df31c0ef5ac36f943",
        "crontab.5",
        Some("1.7.2"),
        None,
        Some("cronie-1.7.2-v1"),
        CRONIE_CITATIONS,
    ),
    contract(
        "anacron.v1.scheduler.v1",
        "anacron.v1.scheduler.v1",
        CatalogScope::Provider(Provider::Anacron),
        AuthorityRole::SchedulerSemantics,
        "cronie-crond",
        "5f9f16b5663becefdd0dd70df31c0ef5ac36f943",
        "anacron.8",
        Some("1.7.2"),
        None,
        Some("anacron-1.7.2-v1"),
        ANACRON_CITATIONS,
    ),
    contract(
        "fcron.v3.4.0.scheduler.v1",
        "fcron.v3.4.0.scheduler.v1",
        CatalogScope::Provider(Provider::Fcron),
        AuthorityRole::SchedulerSemantics,
        "yo8192/fcron",
        "8198d4b90690fb0f53cca931b6e9bb6d4b9e6f83",
        "doc/en/fcrontab.5.sgml",
        Some("3.4.0"),
        None,
        Some("fcron-3.4.0-v1"),
        FCRON_CITATIONS,
    ),
    contract(
        "fcron.v3.4.1.scheduler.v1",
        "fcron.v3.4.1.scheduler.v1",
        CatalogScope::Provider(Provider::Fcron),
        AuthorityRole::SchedulerSemantics,
        "yo8192/fcron",
        "a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130",
        "doc/en/fcrontab.5.sgml",
        Some("3.4.1"),
        None,
        Some("fcron-3.4.1-v1"),
        FCRON_341_CITATIONS,
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_catalog_is_exact_and_offline_valid() {
        assert_eq!(CATALOG.len(), 10);
        assert!(catalog_check().is_ok());
        let darwin = CATALOG[1];
        assert_eq!(darwin.family_id().as_str(), "nix-darwin.gc.mapping.v1");
        assert_eq!(
            darwin.fingerprint(),
            Some("nix-darwin-gc-launchd-mapping-v1")
        );
        assert_eq!(darwin.citations().len(), 2);
        assert_eq!(darwin.lifecycle().state(), LifecycleState::Active);
        assert_eq!(darwin.lifecycle().first_audited_on(), "2026-07-17");
        const WRONG_OWNER: &[SourceCitation] = &[SourceCitation {
            title: "wrong owner",
            url: "https://github.com/evil/nix/blob/035f34f13f969cf72ca4ea60369d907972402956/source",
        }];
        let mut invalid = CATALOG[0];
        invalid.citations = WRONG_OWNER;
        assert!(matches!(
            validate_catalog(&[invalid]),
            Err(CatalogError::InvalidCitation)
        ));
    }

    #[test]
    fn roles_are_independent_and_exact_misses_are_unknown() {
        let catalog = embedded_catalog();
        let identity = ObservedAuthorityIdentity::contract_with_fingerprint(
            "systemd",
            "de9dbc37ad4aa637e200ac02a0545095997055df",
            "systemd.timer.xml",
            Some("261"),
            None,
            Some("systemd-v261-v1"),
        )
        .unwrap();
        let resolved = catalog.resolve(
            AuthorityRole::SchedulerSemantics,
            CatalogScope::Provider(Provider::NixOsSystemd),
            &identity,
        );
        assert!(matches!(resolved, AuthorityResolution::Resolved(_)));
        assert!(matches!(
            catalog.resolve(
                AuthorityRole::AutomationMapping,
                CatalogScope::Provider(Provider::NixOsSystemd),
                &identity,
            ),
            AuthorityResolution::Unresolved(AuthorityUnknownReason::IdentityNotCatalogued)
        ));
        assert!(matches!(
            catalog.resolve(
                AuthorityRole::SchedulerSemantics,
                CatalogScope::Provider(Provider::NixOsSystemd),
                &ObservedAuthorityIdentity::contract_with_fingerprint(
                    "systemd",
                    "de9dbc37ad4aa637e200ac02a0545095997055df",
                    "systemd.timer.xml",
                    Some("262~devel"),
                    None,
                    Some("systemd-v262-devel-v1"),
                )
                .unwrap(),
            ),
            AuthorityResolution::Unresolved(AuthorityUnknownReason::IdentityNotCatalogued)
        ));
    }

    #[test]
    fn mapping_requires_the_complete_normalized_fingerprint() {
        let catalog = embedded_catalog();
        let exact = ObservedAuthorityIdentity::source_with_fingerprint(
            "NixOS/nixpkgs",
            "e8d924d50a462f89166e31a27bdcbbade35fd8e6",
            Some("nixos-gc-systemd-mapping-v1"),
        )
        .unwrap();
        assert!(matches!(
            catalog.resolve(
                AuthorityRole::AutomationMapping,
                CatalogScope::Provider(Provider::NixOsSystemd),
                &exact,
            ),
            AuthorityResolution::Resolved(_)
        ));
        let missing = ObservedAuthorityIdentity::source(
            "NixOS/nixpkgs",
            "e8d924d50a462f89166e31a27bdcbbade35fd8e6",
        )
        .unwrap();
        assert!(matches!(
            catalog.resolve(
                AuthorityRole::AutomationMapping,
                CatalogScope::Provider(Provider::NixOsSystemd),
                &missing,
            ),
            AuthorityResolution::Unresolved(AuthorityUnknownReason::ExactBasisUnverifiable)
        ));
        let wrong = ObservedAuthorityIdentity::source_with_fingerprint(
            "NixOS/nixpkgs",
            "e8d924d50a462f89166e31a27bdcbbade35fd8e6",
            Some("wrong-fingerprint"),
        )
        .unwrap();
        assert!(matches!(
            catalog.resolve(
                AuthorityRole::AutomationMapping,
                CatalogScope::Provider(Provider::NixOsSystemd),
                &wrong,
            ),
            AuthorityResolution::Unresolved(AuthorityUnknownReason::ExactBasisUnverifiable)
        ));
    }

    #[test]
    fn unavailable_and_malformed_identity_stay_unknown() {
        let catalog = embedded_catalog();
        assert!(matches!(
            catalog.resolve_observation(
                AuthorityRole::SchedulerSemantics,
                CatalogScope::Provider(Provider::NixOsSystemd),
                &AuthorityIdentityObservation::Unavailable,
            ),
            AuthorityResolution::Unresolved(AuthorityUnknownReason::IdentityUnavailable)
        ));
        assert!(matches!(
            catalog.resolve_observation(
                AuthorityRole::SchedulerSemantics,
                CatalogScope::Provider(Provider::NixOsSystemd),
                &AuthorityIdentityObservation::Malformed,
            ),
            AuthorityResolution::Unresolved(AuthorityUnknownReason::IdentityMalformed)
        ));
    }

    #[test]
    fn lifecycle_states_validate_and_tombstones_stop_resolution() {
        let revision = "035f34f13f969cf72ca4ea60369d907972402956";
        let mut deprecated = source(
            "synthetic.deprecated",
            "synthetic.deprecated",
            CatalogScope::Nix,
            AuthorityRole::GcOperationSemantics,
            "NixOS/nix",
            revision,
            Some("nix-gc-operation-v1"),
            NIX_CITATIONS,
        );
        deprecated.lifecycle = Lifecycle {
            state: LifecycleState::Deprecated,
            first_audited_on: "2026-07-16",
            last_audited_on: "2026-07-17",
            transitioned_on: Some("2026-07-17"),
            reason: Some("superseded"),
            replacement: None,
        };
        assert!(validate_catalog(&[deprecated]).is_ok());
        let identity = ObservedAuthorityIdentity::source_with_fingerprint(
            "NixOS/nix",
            revision,
            Some("nix-gc-operation-v1"),
        )
        .unwrap();
        assert!(matches!(
            resolve_entries(
                &[deprecated],
                AuthorityRole::GcOperationSemantics,
                CatalogScope::Nix,
                &identity,
            ),
            AuthorityResolution::Resolved(_)
        ));
        let mut tombstone = deprecated;
        tombstone.lifecycle.state = LifecycleState::Tombstoned;
        assert!(matches!(
            resolve_entries(
                &[tombstone],
                AuthorityRole::GcOperationSemantics,
                CatalogScope::Nix,
                &identity,
            ),
            AuthorityResolution::Unresolved(AuthorityUnknownReason::ExactBasisUnverifiable)
        ));
        let mut invalid_active = source(
            "synthetic.invalid",
            "synthetic.invalid",
            CatalogScope::Nix,
            AuthorityRole::GcOperationSemantics,
            "NixOS/nix",
            revision,
            Some("nix-gc-operation-v1"),
            NIX_CITATIONS,
        );
        invalid_active.lifecycle.reason = Some("unexpected");
        assert!(matches!(
            validate_catalog(&[invalid_active]),
            Err(CatalogError::InvalidLifecycle)
        ));
    }

    #[test]
    fn source_identity_uses_exact_repository_and_revision() {
        let catalog = embedded_catalog();
        let identity = ObservedAuthorityIdentity::source_with_fingerprint(
            "NixOS/nix",
            "035f34f13f969cf72ca4ea60369d907972402956",
            Some("nix-gc-operation-v1"),
        )
        .unwrap();
        assert!(matches!(
            catalog.resolve(
                AuthorityRole::GcOperationSemantics,
                CatalogScope::Nix,
                &identity
            ),
            AuthorityResolution::Resolved(_)
        ));
        let wrong_revision = ObservedAuthorityIdentity::source_with_fingerprint(
            "NixOS/nix",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Some("nix-gc-operation-v1"),
        )
        .unwrap();
        assert!(matches!(
            catalog.resolve(
                AuthorityRole::GcOperationSemantics,
                CatalogScope::Nix,
                &wrong_revision
            ),
            AuthorityResolution::Unresolved(AuthorityUnknownReason::IdentityNotCatalogued)
        ));
    }

    #[test]
    fn identities_require_full_revisions_and_safe_text() {
        assert!(ObservedAuthorityIdentity::source("NixOS/nix", "short").is_err());
        assert!(ObservedAuthorityIdentity::source("NixOS/nix", &"a".repeat(40)).is_ok());
        assert!(
            ObservedAuthorityIdentity::source("/Library/LaunchDaemons", &"a".repeat(40)).is_err()
        );
        assert!(
            ObservedAuthorityIdentity::contract(
                "systemd",
                "de9dbc37ad4aa637e200ac02a0545095997055df",
                "systemd.timer.xml",
                Some("261"),
                Some("\u{7f}"),
            )
            .is_err()
        );
        assert!(valid_date("2026-07-17"));
        assert!(!valid_date("2026-13-01"));
        assert!(!valid_date("2026/07/17"));
    }

    #[test]
    fn debug_does_not_contain_runtime_scheduler_data() {
        let debug = format!(
            "{:?}",
            ObservedAuthorityIdentity::source(
                "NixOS/nix",
                "035f34f13f969cf72ca4ea60369d907972402956",
            )
            .unwrap()
        );
        assert!(!debug.contains("/Library/LaunchDaemons"));
        assert!(!debug.contains("nix-collect-garbage --delete-old"));
    }
}
