use crate::evidence::Provider;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthorityRole {
    GcOperationSemantics,
    AutomationMapping,
    SchedulerSemantics,
}

impl AuthorityRole {
    pub const fn index(self) -> usize {
        match self {
            Self::GcOperationSemantics => 0,
            Self::AutomationMapping => 1,
            Self::SchedulerSemantics => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum AuthorityUnknownReason {
    IdentityUnavailable,
    IdentityMalformed,
    IdentityNotCatalogued,
    ExactBasisUnverifiable,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // Resolved keeps the complete static authority metadata.
pub enum AuthorityResolution {
    Resolved(AuthorityRef),
    Unresolved(AuthorityUnknownReason),
    NotClaimed,
    NotApplicable,
}

impl fmt::Debug for AuthorityResolution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolved(_) => formatter.write_str("Resolved(<catalogued>)"),
            Self::Unresolved(reason) => formatter.debug_tuple("Unresolved").field(reason).finish(),
            Self::NotClaimed => formatter.write_str("NotClaimed"),
            Self::NotApplicable => formatter.write_str("NotApplicable"),
        }
    }
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
    source: SourcePin,
    digest: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct PackageIdentity {
    provider: Provider,
    version: &'static str,
    nixpkgs_revision: FullRevision,
    source_digest: &'static str,
    patch_digests: &'static [&'static str],
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedPackageIdentity {
    provider: Provider,
    version: String,
    nixpkgs_revision: String,
    source_digest: String,
    patch_digests: Vec<String>,
}
#[allow(dead_code)]
impl ObservedPackageIdentity {
    pub fn new(
        provider: Provider,
        version: &str,
        nixpkgs_revision: &str,
        source_digest: &str,
        patch_digests: &[&str],
    ) -> Result<Self, CatalogError> {
        if !valid_identity_text(version)
            || !valid_revision_text(nixpkgs_revision)
            || !valid_digest(source_digest)
            || patch_digests.iter().any(|d| !valid_digest(d))
        {
            return Err(CatalogError::InvalidIdentity);
        }
        Ok(Self {
            provider,
            version: version.to_owned(),
            nixpkgs_revision: nixpkgs_revision.to_owned(),
            source_digest: source_digest.to_owned(),
            patch_digests: patch_digests.iter().map(|d| (*d).to_owned()).collect(),
        })
    }
    fn matches(&self, expected: PackageIdentity) -> bool {
        self.provider == expected.provider
            && self.version == expected.version
            && self.nixpkgs_revision == expected.nixpkgs_revision.0
            && self.source_digest == expected.source_digest
            && self.patch_digests.len() == expected.patch_digests.len()
            && self
                .patch_digests
                .iter()
                .zip(expected.patch_digests)
                .all(|(actual, expected)| actual == expected)
    }
}
pub enum PackageIdentityObservation {
    Known(ObservedPackageIdentity),
    Unavailable,
    Malformed,
}
impl IntegrityPin {
    pub const fn label(self) -> &'static str {
        self.label
    }
    pub const fn source(self) -> SourcePin {
        self.source
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
        validate_catalog(self.entries())?;
        validate_package_identities(PACKAGE_IDENTITIES)
    }

    #[allow(dead_code)] // consumed by the report classifier child after this catalog slice.
    pub(crate) fn resolve(
        self,
        role: AuthorityRole,
        scope: CatalogScope,
        identity: &ObservedAuthorityIdentity,
    ) -> AuthorityResolution {
        // LLM contract: cron mapping is NotClaimed; pure and read-only.
        if cron_mapping_is_not_claimed(role, scope) {
            return AuthorityResolution::NotClaimed;
        }
        resolve_entries(self.entries(), role, scope, identity)
    }

    // LLM contract: exact package+ContractPin resolves; unknown/mismatch is Unresolved; pure/read-only.
    #[allow(dead_code)]
    pub(crate) fn resolve_cron_scheduler_semantics(
        self,
        provider: Provider,
        package: &PackageIdentityObservation,
        contract: &AuthorityIdentityObservation,
    ) -> AuthorityResolution {
        let package = match package {
            PackageIdentityObservation::Known(package) => package,
            PackageIdentityObservation::Unavailable => {
                return AuthorityResolution::Unresolved(
                    AuthorityUnknownReason::IdentityUnavailable,
                );
            }
            PackageIdentityObservation::Malformed => {
                return AuthorityResolution::Unresolved(AuthorityUnknownReason::IdentityMalformed);
            }
        };
        let Some(expected) = PACKAGE_IDENTITIES
            .iter()
            .copied()
            .find(|identity| identity.provider == provider && identity.version == package.version)
        else {
            return AuthorityResolution::Unresolved(AuthorityUnknownReason::IdentityNotCatalogued);
        };
        if !package.matches(expected) {
            return AuthorityResolution::Unresolved(AuthorityUnknownReason::ExactBasisUnverifiable);
        }
        if let AuthorityIdentityObservation::Known(identity) = contract
            && !package_contract_matches(provider, &package.version, identity)
        {
            return AuthorityResolution::Unresolved(AuthorityUnknownReason::ExactBasisUnverifiable);
        }
        self.resolve_observation(
            AuthorityRole::SchedulerSemantics,
            CatalogScope::Provider(provider),
            contract,
        )
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
        if cron_mapping_is_not_claimed(role, scope) {
            return AuthorityResolution::NotClaimed;
        }
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

fn cron_mapping_is_not_claimed(role: AuthorityRole, scope: CatalogScope) -> bool {
    role == AuthorityRole::AutomationMapping
        && matches!(
            scope,
            CatalogScope::Provider(Provider::Cronie | Provider::Anacron | Provider::Fcron)
        )
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

#[allow(dead_code)]
fn package_contract_matches(
    provider: Provider,
    version: &str,
    identity: &ObservedAuthorityIdentity,
) -> bool {
    let expected = match (provider, version) {
        (Provider::Cronie | Provider::Anacron, "1.7.2") => {
            "71894fee3c74f3787e77f21a24fbbe0dffb59e7f"
        }
        (Provider::Fcron, "3.4.0") => "8198d4b90690fb0f53cca931b6e9bb6d4b9e6f83",
        _ => return false,
    };
    matches!(&identity.0, IdentityKind::Contract { revision, build, .. } if revision == expected && build.as_deref() == Some(version))
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
        if entry.integrity.iter().any(|pin| {
            !valid_text(pin.label)
                || !valid_digest(pin.digest)
                || !valid_identity_text(pin.source.repository)
                || !valid_revision_text(pin.source.revision.0)
        }) {
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

fn validate_package_identities(identities: &[PackageIdentity]) -> Result<(), CatalogError> {
    if identities.iter().any(|i| {
        !matches!(
            i.provider,
            Provider::Cronie | Provider::Anacron | Provider::Fcron
        ) || !valid_identity_text(i.version)
            || !valid_revision_text(i.nixpkgs_revision.0)
            || !valid_digest(i.source_digest)
            || i.patch_digests.is_empty()
            || i.patch_digests.iter().any(|d| !valid_digest(d))
    }) {
        return Err(CatalogError::InvalidIdentity);
    }
    if identities.iter().enumerate().any(|(n, i)| {
        identities[..n]
            .iter()
            .any(|other| other.provider == i.provider && other.version == i.version)
    }) {
        return Err(CatalogError::DuplicateIdentity);
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
    source_with_integrity(
        entry_id,
        family_id,
        scope,
        role,
        repository,
        revision,
        fingerprint,
        citations,
        &[],
    )
}

#[allow(clippy::too_many_arguments)]
const fn source_with_integrity(
    entry_id: &'static str,
    family_id: &'static str,
    scope: CatalogScope,
    role: AuthorityRole,
    repository: &'static str,
    revision: &'static str,
    fingerprint: Option<&'static str>,
    citations: &'static [SourceCitation],
    integrity: &'static [IntegrityPin],
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
        integrity,
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
        title: "Nix store command implementation",
        url: "https://github.com/NixOS/nix/blob/035f34f13f969cf72ca4ea60369d907972402956/src/nix/nix-store/nix-store.cc",
    },
    SourceCitation {
        title: "Nix store garbage collection implementation",
        url: "https://github.com/NixOS/nix/blob/035f34f13f969cf72ca4ea60369d907972402956/src/nix/store-gc.cc",
    },
    SourceCitation {
        title: "Nix garbage collection command manual",
        url: "https://github.com/NixOS/nix/blob/035f34f13f969cf72ca4ea60369d907972402956/doc/manual/source/command-ref/nix-collect-garbage.md",
    },
    SourceCitation {
        title: "Nix store garbage collection manual",
        url: "https://github.com/NixOS/nix/blob/035f34f13f969cf72ca4ea60369d907972402956/doc/manual/source/command-ref/nix-store/gc.md",
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
const SYSTEMD_DBUS_CITATIONS: &[SourceCitation] = &[SourceCitation {
    title: "systemd D-Bus manager and service contract",
    url: "https://github.com/systemd/systemd/blob/de9dbc37ad4aa637e200ac02a0545095997055df/man/org.freedesktop.systemd1.xml",
}];
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
    url: "https://github.com/cronie-crond/cronie/blob/71894fee3c74f3787e77f21a24fbbe0dffb59e7f/man/crontab.5",
}];
const ANACRON_CITATIONS: &[SourceCitation] = &[SourceCitation {
    title: "anacron runtime contract",
    url: "https://github.com/cronie-crond/cronie/blob/71894fee3c74f3787e77f21a24fbbe0dffb59e7f/man/anacron.8",
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

const NIXOS_INTEGRITY: &[IntegrityPin] = &[
    IntegrityPin {
        label: "systemd-261-package-source",
        source: SourcePin {
            repository: "NixOS/nixpkgs",
            revision: FullRevision("6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee"),
        },
        digest: "e8807564442a4348a6a7006109a2d900480c56454553ad490d5946a2dc4dcc64",
    },
    IntegrityPin {
        label: "nixpkgs-package-and-compatibility-patches",
        source: SourcePin {
            repository: "NixOS/nixpkgs",
            revision: FullRevision("6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee"),
        },
        digest: "16689e241f3f394bcdc5b91ba22efe2067c8b925d8de717f859426f240f4af9d",
    },
];

const CRONIE_PATCH_DIGESTS: &[&str] =
    &["394ea90857843c2df670f1372bd52af47bafa70754669681b72c4d39a2641553"];
const FCRON_PATCH_DIGESTS: &[&str] =
    &["245d7f3c07386bf586bad9452b2399cfaba6f88a8f33e6cd125d632b164e21a2"];
const CRONIE_SOURCE_DIGEST: &str =
    "5abcdda44f6deef5a973c405a05b3e4bf1e01f0b227513667dc1e9ee5b52590c";
const FCRON_SOURCE_DIGEST: &str =
    "f4e7fc553cdd70ff4b3b6ac9138b3b7cffab9198b8c266d97af0a87506e0e1b5";
const CRON_NIXPKGS_REVISION: FullRevision =
    FullRevision("6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee");

const PACKAGE_IDENTITIES: &[PackageIdentity] = &[
    PackageIdentity {
        provider: Provider::Cronie,
        version: "1.7.2",
        nixpkgs_revision: CRON_NIXPKGS_REVISION,
        source_digest: CRONIE_SOURCE_DIGEST,
        patch_digests: CRONIE_PATCH_DIGESTS,
    },
    PackageIdentity {
        provider: Provider::Anacron,
        version: "1.7.2",
        nixpkgs_revision: CRON_NIXPKGS_REVISION,
        source_digest: CRONIE_SOURCE_DIGEST,
        patch_digests: CRONIE_PATCH_DIGESTS,
    },
    PackageIdentity {
        provider: Provider::Fcron,
        version: "3.4.0",
        nixpkgs_revision: CRON_NIXPKGS_REVISION,
        source_digest: FCRON_SOURCE_DIGEST,
        patch_digests: FCRON_PATCH_DIGESTS,
    },
];

const CATALOG: [AuthorityRef; 11] = [
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
    source_with_integrity(
        "nixos.gc.mapping.v1",
        "nixos.gc.mapping.v1",
        CatalogScope::Provider(Provider::NixOsSystemd),
        AuthorityRole::AutomationMapping,
        "NixOS/nixpkgs",
        "e8d924d50a462f89166e31a27bdcbbade35fd8e6",
        Some("nixos-gc-systemd-mapping-v1"),
        NIXOS_CITATIONS,
        NIXOS_INTEGRITY,
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
        "systemd.v261.dbus.v1",
        "systemd.v261.dbus.v1",
        CatalogScope::Provider(Provider::NixOsSystemd),
        AuthorityRole::SchedulerSemantics,
        "systemd",
        "de9dbc37ad4aa637e200ac02a0545095997055df",
        "org.freedesktop.systemd1.xml",
        Some("261"),
        None,
        Some("systemd-v261-dbus-v1"),
        SYSTEMD_DBUS_CITATIONS,
    ),
    contract(
        "cronie.v1.scheduler.v1",
        "cronie.v1.scheduler.v1",
        CatalogScope::Provider(Provider::Cronie),
        AuthorityRole::SchedulerSemantics,
        "cronie-crond",
        "71894fee3c74f3787e77f21a24fbbe0dffb59e7f",
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
        "71894fee3c74f3787e77f21a24fbbe0dffb59e7f",
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
        assert_eq!(CATALOG.len(), 11);
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
        let nixos = CATALOG[2];
        assert_eq!(nixos.integrity().len(), 2);
        assert_eq!(
            nixos.integrity()[0].source().revision().as_str(),
            "6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee"
        );
        let dbus = CATALOG
            .iter()
            .find(|entry| entry.entry_id().as_str() == "systemd.v261.dbus.v1")
            .expect("pinned D-Bus contract");
        assert!(matches!(
            dbus.pin(),
            AuthorityPin::Contract(pin) if pin.contract() == "org.freedesktop.systemd1.xml"
        ));
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
        assert_eq!(
            catalog.resolve(
                AuthorityRole::AutomationMapping,
                CatalogScope::Provider(Provider::Cronie),
                &exact
            ),
            AuthorityResolution::NotClaimed
        );
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

    #[test]
    fn integrity_pins_require_sha256_digests() {
        let mut entry = CATALOG[0];
        const INVALID: &[IntegrityPin] = &[IntegrityPin {
            label: "package",
            source: SourcePin {
                repository: "NixOS/nixpkgs",
                revision: FullRevision("e8d924d50a462f89166e31a27bdcbbade35fd8e6"),
            },
            digest: "not-a-digest",
        }];
        entry.integrity = INVALID;
        assert!(matches!(
            validate_catalog(&[entry]),
            Err(CatalogError::InvalidIdentity)
        ));
    }

    #[test]
    fn cron_scheduler_requires_exact_package_and_contract_pins() {
        let catalog = embedded_catalog();
        let package = |provider, version, revision, source, patches| {
            ObservedPackageIdentity::new(provider, version, revision, source, patches).unwrap()
        };
        let contract = |publisher, revision, name, build, fingerprint| {
            AuthorityIdentityObservation::Known(
                ObservedAuthorityIdentity::contract_with_fingerprint(
                    publisher,
                    revision,
                    name,
                    build,
                    None,
                    Some(fingerprint),
                )
                .unwrap(),
            )
        };
        let official_tag = contract(
            "cronie-crond",
            "71894fee3c74f3787e77f21a24fbbe0dffb59e7f",
            "crontab.5",
            Some("1.7.2"),
            "cronie-1.7.2-v1",
        );
        let assert_reason = |provider, package, contract, reason| {
            assert_eq!(
                catalog.resolve_cron_scheduler_semantics(provider, &package, contract),
                reason
            );
        };
        let observed = package(
            Provider::Cronie,
            "1.7.2",
            CRON_NIXPKGS_REVISION.0,
            CRONIE_SOURCE_DIGEST,
            CRONIE_PATCH_DIGESTS,
        );
        assert_reason(
            Provider::Cronie,
            PackageIdentityObservation::Known(observed.clone()),
            &official_tag,
            AuthorityResolution::Resolved(CATALOG[7]),
        );
        let mut wrong_revision = observed.clone();
        wrong_revision.nixpkgs_revision.replace_range(0..1, "7");
        assert_reason(
            Provider::Cronie,
            PackageIdentityObservation::Known(wrong_revision),
            &official_tag,
            AuthorityResolution::Unresolved(AuthorityUnknownReason::ExactBasisUnverifiable),
        );
        let mut wrong_source = observed.clone();
        wrong_source.source_digest.replace_range(0..1, "6");
        assert_reason(
            Provider::Cronie,
            PackageIdentityObservation::Known(wrong_source),
            &official_tag,
            AuthorityResolution::Unresolved(AuthorityUnknownReason::ExactBasisUnverifiable),
        );
        let mut wrong_patch = observed.clone();
        wrong_patch.patch_digests[0].replace_range(0..1, "4");
        assert_reason(
            Provider::Cronie,
            PackageIdentityObservation::Known(wrong_patch),
            &official_tag,
            AuthorityResolution::Unresolved(AuthorityUnknownReason::ExactBasisUnverifiable),
        );
        assert_reason(
            Provider::Cronie,
            PackageIdentityObservation::Unavailable,
            &official_tag,
            AuthorityResolution::Unresolved(AuthorityUnknownReason::IdentityUnavailable),
        );
        let fcron = package(
            Provider::Fcron,
            "3.4.0",
            CRON_NIXPKGS_REVISION.0,
            FCRON_SOURCE_DIGEST,
            FCRON_PATCH_DIGESTS,
        );
        let mut unknown = fcron.clone();
        unknown.version = "3.4.1".into();
        assert_reason(
            Provider::Fcron,
            PackageIdentityObservation::Known(unknown),
            &official_tag,
            AuthorityResolution::Unresolved(AuthorityUnknownReason::IdentityNotCatalogued),
        );
        let post_tag = contract(
            "cronie-crond",
            "5f9f16b5663becefdd0dd70df31c0ef5ac36f943",
            "crontab.5",
            Some("1.7.2"),
            "cronie-1.7.2-v1",
        );
        let official = PackageIdentityObservation::Known(observed);
        assert_reason(
            Provider::Cronie,
            official,
            &post_tag,
            AuthorityResolution::Unresolved(AuthorityUnknownReason::ExactBasisUnverifiable),
        );
    }
}
