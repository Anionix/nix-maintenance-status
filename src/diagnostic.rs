use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProbeFailure {
    CommandUnavailable,
    CommandFailed,
    FileSystemUnavailable,
    MalformedOutput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe<T> {
    Observed(T),
    Absent,
    Unavailable(ProbeFailure),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GcPlist(());
impl GcPlist {
    pub const fn new() -> Self {
        Self(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LaunchdJob(());
impl LaunchdJob {
    pub const fn new() -> Self {
        Self(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacOsEvidence(pub(crate) Probe<GcPlist>, pub(crate) Probe<LaunchdJob>);
impl MacOsEvidence {
    pub fn new(plist: Probe<GcPlist>, launchd: Probe<LaunchdJob>) -> Self {
        Self(plist, launchd)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TargetPlatform {
    MacOs,
    Linux,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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
    pub const fn start(&self) -> SystemTime {
        self.start
    }
    pub const fn duration(&self) -> Duration {
        self.duration
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InputError {
    InvalidPlatformProvider,
    DuplicateEvidenceKey,
    DanglingEvidenceReference,
    InvalidScanWindow,
    InvalidSubject,
    InvalidNormalizedValue,
    CardinalityExceeded,
    InconsistentInput,
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
impl Provider {
    #[allow(non_upper_case_globals)]
    pub const Launchd: Self = Self::NixDarwinLaunchd;
    #[allow(non_upper_case_globals)]
    pub const Systemd: Self = Self::NixOsSystemd;
    pub const fn catalog_id(self) -> &'static str {
        match self {
            Self::NixDarwinLaunchd => "nix-darwin.launchd",
            Self::NixOsSystemd => "nixos.systemd",
            Self::Cronie => "cronie",
            Self::Anacron => "anacron",
            Self::Fcron => "fcron",
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
    pub const fn unresolved(ordinal: u32) -> Self {
        Self::Unresolved(ordinal)
    }
    pub fn render(self) -> String {
        match self {
            Self::System => "system".into(),
            Self::Uid(uid) => format!("uid:{uid}"),
            Self::Unresolved(n) => format!("subject:unresolved:{n}"),
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

#[derive(Debug, Clone, PartialEq, Eq)]
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
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderEvidenceSet(Vec<ProviderEvidence>);
impl ProviderEvidenceSet {
    pub fn new(mut values: Vec<ProviderEvidence>) -> Result<Self, InputError> {
        if values.len() > 4096 {
            return Err(InputError::CardinalityExceeded);
        }
        if values
            .iter()
            .any(|value| value.subject == Subject::Unresolved(0))
        {
            return Err(InputError::InvalidSubject);
        }
        values.sort_by_key(|value| (value.provider, value.subject, value.component));
        if values.windows(2).any(|pair| {
            (pair[0].provider, pair[0].subject, pair[0].component)
                == (pair[1].provider, pair[1].subject, pair[1].component)
        }) {
            return Err(InputError::DuplicateEvidenceKey);
        }
        Ok(Self(values))
    }
    pub fn empty() -> Self {
        Self::default()
    }
    pub fn entries(&self) -> &[ProviderEvidence] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EvidenceId(u32);

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Evidence {
    Observation {
        provider: Provider,
        subject: Subject,
        component: ObservationComponent,
        presence: Presence,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvidenceSet {
    items: Vec<(EvidenceId, Evidence)>,
}
impl EvidenceSet {
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = (EvidenceId, &Evidence)> {
        self.items.iter().map(|(id, value)| (*id, value))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceClass {
    Observed,
    Inferred,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthorityRole {
    GcOperationSemantics,
    AutomationMapping,
    SchedulerSemantics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthorityUnknownReason {
    IdentityUnavailable,
    IdentityMalformed,
    IdentityNotCatalogued,
    ExactBasisUnverifiable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityRef {
    identity: &'static str,
}
impl AuthorityRef {
    pub const fn identity(&self) -> &'static str {
        self.identity
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityResolution {
    Resolved(AuthorityRef),
    Unresolved(AuthorityUnknownReason),
    NotClaimed,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityRoles {
    gc_operation: AuthorityResolution,
    automation_mapping: AuthorityResolution,
    scheduler: AuthorityResolution,
}
impl AuthorityRoles {
    pub const fn gc_operation(&self) -> AuthorityResolution {
        self.gc_operation
    }
    pub const fn automation_mapping(&self) -> AuthorityResolution {
        self.automation_mapping
    }
    pub const fn scheduler(&self) -> AuthorityResolution {
        self.scheduler
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    class: EvidenceClass,
    evidence: Vec<EvidenceId>,
    authority: AuthorityRoles,
}
impl Provenance {
    pub const fn evidence_class(&self) -> EvidenceClass {
        self.class
    }
    pub fn evidence_ids(&self) -> &[EvidenceId] {
        &self.evidence
    }
    pub const fn authority(&self) -> AuthorityRoles {
        self.authority
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Conclusion<T> {
    Known(T),
    Unknown(UnknownReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applicability<T> {
    Applicable(T),
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnknownReason {
    ProbeFailed(ProbeFailure),
    Unavailable(UnavailableReason),
    Authority(AuthorityUnknownReason),
    DependentClaimUnknown,
    UnresolvedExecutableIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim<T> {
    conclusion: Conclusion<T>,
    provenance: Provenance,
}
impl<T> Claim<T> {
    pub const fn conclusion(&self) -> &Conclusion<T> {
        &self.conclusion
    }
    pub const fn provenance(&self) -> &Provenance {
        &self.provenance
    }
    fn known(
        value: T,
        class: EvidenceClass,
        evidence: Vec<EvidenceId>,
        authority: AuthorityRoles,
    ) -> Self {
        Self {
            conclusion: Conclusion::Known(value),
            provenance: Provenance {
                class,
                evidence,
                authority,
            },
        }
    }
    fn unknown(
        reason: UnknownReason,
        evidence: Vec<EvidenceId>,
        authority: AuthorityRoles,
    ) -> Self {
        Self {
            conclusion: Conclusion::Unknown(reason),
            provenance: Provenance {
                class: EvidenceClass::Unknown,
                evidence,
                authority,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigurationState {
    ConsistentWithNixDarwinAutomaticGc,
    NotDetected,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RuntimeState {
    Loaded,
    NotLoaded,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConsistencyState {
    Consistent,
    Inconsistent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutomationClaims {
    configuration: Claim<ConfigurationState>,
    runtime: Claim<RuntimeState>,
    consistency: Claim<ConsistencyState>,
    schedule: Claim<Applicability<()>>,
    command: Claim<Applicability<()>>,
    activity: Claim<Applicability<()>>,
    runs: Claim<Applicability<()>>,
    last_result: Claim<Applicability<()>>,
}
impl AutomationClaims {
    pub const fn configuration(&self) -> &Claim<ConfigurationState> {
        &self.configuration
    }
    pub const fn runtime(&self) -> &Claim<RuntimeState> {
        &self.runtime
    }
    pub const fn consistency(&self) -> &Claim<ConsistencyState> {
        &self.consistency
    }
    pub const fn schedule(&self) -> &Claim<Applicability<()>> {
        &self.schedule
    }
    pub const fn command(&self) -> &Claim<Applicability<()>> {
        &self.command
    }
    pub const fn activity(&self) -> &Claim<Applicability<()>> {
        &self.activity
    }
    pub const fn runs(&self) -> &Claim<Applicability<()>> {
        &self.runs
    }
    pub const fn last_result(&self) -> &Claim<Applicability<()>> {
        &self.last_result
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AutomationId(u32);
impl AutomationId {
    pub const fn ordinal(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcAutomation {
    id: AutomationId,
    subject: Subject,
    provider: Provider,
    claims: AutomationClaims,
}
impl GcAutomation {
    pub const fn id(&self) -> AutomationId {
        self.id
    }
    pub const fn subject(&self) -> Subject {
        self.subject
    }
    pub const fn provider(&self) -> Provider {
        self.provider
    }
    pub const fn claims(&self) -> &AutomationClaims {
        &self.claims
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanMetadata {
    scope: ScanScope,
    window: ScanWindow,
}
impl ScanMetadata {
    pub const fn scope(&self) -> ScanScope {
        self.scope
    }
    pub const fn window(&self) -> ScanWindow {
        self.window
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageStatus {
    Complete,
    Partial,
    Unavailable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageLeafStatus {
    Covered,
    Unavailable(UnavailableReason),
    NotApplicable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverageLeaf {
    provider: Provider,
    subject: Subject,
    component: ObservationComponent,
    status: CoverageLeafStatus,
}
impl CoverageLeaf {
    pub const fn provider(&self) -> Provider {
        self.provider
    }
    pub const fn subject(&self) -> Subject {
        self.subject
    }
    pub const fn component(&self) -> ObservationComponent {
        self.component
    }
    pub const fn status(&self) -> CoverageLeafStatus {
        self.status
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageMatrix {
    leaves: Vec<CoverageLeaf>,
}
impl CoverageMatrix {
    pub fn leaves(&self) -> &[CoverageLeaf] {
        &self.leaves
    }
    pub fn status(&self) -> CoverageStatus {
        aggregate(&self.leaves)
    }
}
fn aggregate(leaves: &[CoverageLeaf]) -> CoverageStatus {
    let applicable = leaves
        .iter()
        .filter(|leaf| !matches!(leaf.status, CoverageLeafStatus::NotApplicable))
        .count();
    let covered = leaves
        .iter()
        .filter(|leaf| matches!(leaf.status, CoverageLeafStatus::Covered))
        .count();
    if applicable == 0 || covered == 0 {
        CoverageStatus::Unavailable
    } else if covered < applicable {
        CoverageStatus::Partial
    } else {
        CoverageStatus::Complete
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticInput {
    platform: TargetPlatform,
    scope: ScanScope,
    window: ScanWindow,
    evidence: ProviderEvidenceSet,
    legacy: Option<MacOsEvidence>,
}
impl DiagnosticInput {
    pub fn new(
        platform: TargetPlatform,
        scope: ScanScope,
        window: ScanWindow,
        evidence: ProviderEvidenceSet,
    ) -> Result<Self, InputError> {
        if evidence.entries().is_empty() {
            return Err(InputError::InvalidPlatformProvider);
        }
        if evidence.entries().iter().any(|value| match platform {
            TargetPlatform::MacOs => value.provider != Provider::NixDarwinLaunchd,
            TargetPlatform::Linux => value.provider == Provider::NixDarwinLaunchd,
        }) {
            return Err(InputError::InvalidPlatformProvider);
        }
        if scope == ScanScope::System
            && evidence
                .entries()
                .iter()
                .any(|value| value.subject != Subject::System)
        {
            return Err(InputError::InvalidSubject);
        }
        let mut current_subjects: Vec<_> = evidence
            .entries()
            .iter()
            .filter_map(|value| match value.subject {
                Subject::Uid(uid) => Some(uid),
                Subject::System | Subject::Unresolved(_) => None,
            })
            .collect();
        current_subjects.sort();
        current_subjects.dedup();
        let current_subjects_concrete = evidence
            .entries()
            .iter()
            .all(|value| matches!(value.subject, Subject::Uid(_)));
        if scope == ScanScope::CurrentUser
            && (!current_subjects_concrete || current_subjects.len() != 1)
        {
            return Err(InputError::InvalidSubject);
        }
        Ok(Self {
            platform,
            scope,
            window,
            evidence,
            legacy: None,
        })
    }
    pub fn macos(evidence: MacOsEvidence) -> Self {
        Self {
            platform: TargetPlatform::MacOs,
            scope: ScanScope::Default,
            window: ScanWindow::now(Duration::from_secs(1)).unwrap(),
            evidence: ProviderEvidenceSet::empty(),
            legacy: Some(evidence),
        }
    }
    pub const fn platform(&self) -> TargetPlatform {
        self.platform
    }
    pub const fn scope(&self) -> ScanScope {
        self.scope
    }
    pub const fn window(&self) -> ScanWindow {
        self.window
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcReport {
    scan: ScanMetadata,
    coverage: CoverageMatrix,
    automations: Vec<GcAutomation>,
    evidence: EvidenceSet,
    configuration: Claim<ConfigurationState>,
    runtime: Claim<RuntimeState>,
    consistency: Claim<ConsistencyState>,
}
impl GcReport {
    pub const fn scan(&self) -> &ScanMetadata {
        &self.scan
    }
    pub const fn coverage(&self) -> &CoverageMatrix {
        &self.coverage
    }
    pub fn automations(&self) -> &[GcAutomation] {
        &self.automations
    }
    pub const fn evidence(&self) -> &EvidenceSet {
        &self.evidence
    }
    pub const fn configuration(&self) -> &Claim<ConfigurationState> {
        &self.configuration
    }
    pub const fn runtime(&self) -> &Claim<RuntimeState> {
        &self.runtime
    }
    pub const fn consistency(&self) -> &Claim<ConsistencyState> {
        &self.consistency
    }
}

// LLM contract: each component Evidence triggers only its own leaf and Claim;
// missing components are Unavailable, Unknown never becomes Absent, and the
// Coverage aggregate is observation completeness rather than health/officiality.
// diagnose is pure, deterministic, I/O-free, offline, read-only, and total.
pub fn diagnose(input: DiagnosticInput) -> GcReport {
    let legacy = input.legacy.clone();
    let mut source: Vec<(Provider, Subject, ObservationComponent, Presence)> = match legacy.as_ref()
    {
        Some(value) => vec![
            (
                Provider::NixDarwinLaunchd,
                Subject::System,
                ObservationComponent::Discovery,
                probe_presence(&value.0),
            ),
            (
                Provider::NixDarwinLaunchd,
                Subject::System,
                ObservationComponent::Configuration,
                probe_presence(&value.0),
            ),
            (
                Provider::NixDarwinLaunchd,
                Subject::System,
                ObservationComponent::Runtime,
                probe_presence(&value.1),
            ),
        ],
        None => input
            .evidence
            .0
            .iter()
            .map(|value| {
                (
                    value.provider,
                    value.subject,
                    value.component,
                    value.presence,
                )
            })
            .collect(),
    };
    source.sort_by_key(|(provider, subject, component, _)| (*subject, *provider, *component));
    let mut evidence = EvidenceSet::default();
    let mut leaves = Vec::new();
    for (index, (provider, subject, component, presence)) in source.iter().enumerate() {
        evidence.items.push((
            EvidenceId(index as u32),
            Evidence::Observation {
                provider: *provider,
                subject: *subject,
                component: *component,
                presence: *presence,
            },
        ));
        leaves.push(CoverageLeaf {
            provider: *provider,
            subject: *subject,
            component: *component,
            status: leaf_status(*presence),
        });
    }
    let mut subjects: Vec<_> = source.iter().map(|(_, subject, _, _)| *subject).collect();
    subjects.sort();
    subjects.dedup();
    for provider in providers(input.platform) {
        for subject in &subjects {
            let discovery = source
                .iter()
                .find(|(p, s, c, _)| {
                    p == provider && s == subject && *c == ObservationComponent::Discovery
                })
                .map(|(_, _, _, value)| *value);
            for component in COMPONENTS {
                if !source
                    .iter()
                    .any(|(p, s, c, _)| p == provider && s == subject && *c == component)
                {
                    let status = match discovery {
                        Some(Presence::Absent | Presence::PresentEmpty) => {
                            CoverageLeafStatus::NotApplicable
                        }
                        Some(Presence::Unavailable(reason)) => {
                            CoverageLeafStatus::Unavailable(reason)
                        }
                        Some(Presence::Present) | None => {
                            CoverageLeafStatus::Unavailable(UnavailableReason::InterfaceUnavailable)
                        }
                    };
                    leaves.push(CoverageLeaf {
                        provider: *provider,
                        subject: *subject,
                        component,
                        status,
                    });
                }
            }
        }
    }
    let mut candidates: Vec<_> = source
        .iter()
        .filter(|(_, _, component, presence)| {
            *component == ObservationComponent::Discovery && matches!(presence, Presence::Present)
        })
        .map(|(provider, subject, _, _)| (*provider, *subject))
        .collect();
    candidates.sort_by_key(|(provider, subject)| (*subject, *provider));
    candidates.dedup();
    let automations = candidates
        .iter()
        .enumerate()
        .map(|(ordinal, (provider, subject))| {
            let id = evidence_id(&evidence, *provider, *subject, None).unwrap();
            let runtime_id = evidence_id(
                &evidence,
                *provider,
                *subject,
                Some(ObservationComponent::Runtime),
            )
            .unwrap_or(id);
            let roles = unknown_roles();
            let runtime = match source
                .iter()
                .find(|(p, s, c, _)| {
                    p == provider && s == subject && *c == ObservationComponent::Runtime
                })
                .map(|(_, _, _, value)| *value)
            {
                Some(Presence::Present) => known(
                    RuntimeState::Loaded,
                    runtime_id,
                    EvidenceClass::Observed,
                    roles,
                ),
                Some(Presence::Absent) => known(
                    RuntimeState::NotLoaded,
                    runtime_id,
                    EvidenceClass::Observed,
                    roles,
                ),
                Some(Presence::Unavailable(reason)) => {
                    Claim::unknown(UnknownReason::Unavailable(reason), vec![runtime_id], roles)
                }
                _ => Claim::unknown(UnknownReason::DependentClaimUnknown, vec![id], roles),
            };
            GcAutomation {
                id: AutomationId(ordinal as u32),
                subject: *subject,
                provider: *provider,
                claims: AutomationClaims {
                    configuration: Claim::unknown(
                        UnknownReason::Authority(AuthorityUnknownReason::ExactBasisUnverifiable),
                        vec![id],
                        roles,
                    ),
                    runtime,
                    consistency: Claim::unknown(
                        UnknownReason::DependentClaimUnknown,
                        vec![id],
                        roles,
                    ),
                    schedule: unknown_optional(id, roles),
                    command: unknown_optional(id, roles),
                    activity: unknown_optional(id, roles),
                    runs: unknown_optional(id, roles),
                    last_result: unknown_optional(id, roles),
                },
            }
        })
        .collect();
    let (configuration, runtime, consistency) = match legacy {
        Some(value) => legacy_claims(value, EvidenceId(1), EvidenceId(2)),
        None => {
            let ids = evidence
                .items
                .first()
                .map(|(id, _)| vec![*id])
                .unwrap_or_default();
            (
                Claim::unknown(
                    UnknownReason::DependentClaimUnknown,
                    ids.clone(),
                    unknown_roles(),
                ),
                Claim::unknown(
                    UnknownReason::DependentClaimUnknown,
                    ids.clone(),
                    unknown_roles(),
                ),
                Claim::unknown(UnknownReason::DependentClaimUnknown, ids, unknown_roles()),
            )
        }
    };
    GcReport {
        scan: ScanMetadata {
            scope: input.scope,
            window: input.window,
        },
        coverage: CoverageMatrix { leaves },
        automations,
        evidence,
        configuration,
        runtime,
        consistency,
    }
}

const COMPONENTS: [ObservationComponent; 8] = [
    ObservationComponent::Discovery,
    ObservationComponent::Configuration,
    ObservationComponent::Runtime,
    ObservationComponent::Schedule,
    ObservationComponent::Command,
    ObservationComponent::Activity,
    ObservationComponent::Runs,
    ObservationComponent::LastResult,
];
fn probe_presence<T>(probe: &Probe<T>) -> Presence {
    match probe {
        Probe::Observed(_) => Presence::Present,
        Probe::Absent => Presence::Absent,
        Probe::Unavailable(
            ProbeFailure::FileSystemUnavailable | ProbeFailure::CommandUnavailable,
        ) => Presence::Unavailable(UnavailableReason::InterfaceUnavailable),
        Probe::Unavailable(ProbeFailure::CommandFailed) => {
            Presence::Unavailable(UnavailableReason::OperationFailed)
        }
        Probe::Unavailable(ProbeFailure::MalformedOutput) => {
            Presence::Unavailable(UnavailableReason::MalformedEvidence)
        }
    }
}
fn leaf_status(presence: Presence) -> CoverageLeafStatus {
    match presence {
        Presence::Unavailable(reason) => CoverageLeafStatus::Unavailable(reason),
        Presence::Absent | Presence::PresentEmpty | Presence::Present => {
            CoverageLeafStatus::Covered
        }
    }
}
fn evidence_id(
    evidence: &EvidenceSet,
    provider: Provider,
    subject: Subject,
    component: Option<ObservationComponent>,
) -> Option<EvidenceId> {
    evidence.items.iter().find(|(_, item)| matches!(item, Evidence::Observation { provider: p, subject: s, component: c, .. } if *p == provider && *s == subject && component.is_none_or(|wanted| wanted == *c))).map(|(id, _)| *id)
}
fn providers(platform: TargetPlatform) -> &'static [Provider] {
    match platform {
        TargetPlatform::MacOs => &[Provider::NixDarwinLaunchd],
        TargetPlatform::Linux => &[
            Provider::NixOsSystemd,
            Provider::Cronie,
            Provider::Anacron,
            Provider::Fcron,
        ],
    }
}
fn unknown_roles() -> AuthorityRoles {
    AuthorityRoles {
        gc_operation: AuthorityResolution::NotClaimed,
        automation_mapping: AuthorityResolution::Unresolved(
            AuthorityUnknownReason::ExactBasisUnverifiable,
        ),
        scheduler: AuthorityResolution::Unresolved(AuthorityUnknownReason::IdentityUnavailable),
    }
}
fn known<T>(value: T, id: EvidenceId, class: EvidenceClass, authority: AuthorityRoles) -> Claim<T> {
    Claim::known(value, class, vec![id], authority)
}
fn unknown_optional<T>(id: EvidenceId, authority: AuthorityRoles) -> Claim<Applicability<T>> {
    Claim::unknown(UnknownReason::DependentClaimUnknown, vec![id], authority)
}
fn legacy_claims(
    value: MacOsEvidence,
    plist_id: EvidenceId,
    launchd_id: EvidenceId,
) -> (
    Claim<ConfigurationState>,
    Claim<RuntimeState>,
    Claim<ConsistencyState>,
) {
    let (configuration, configured) = claim_from_probe(
        value.0,
        ConfigurationState::ConsistentWithNixDarwinAutomaticGc,
        ConfigurationState::NotDetected,
        EvidenceClass::Inferred,
        plist_id,
    );
    let (runtime, loaded) = claim_from_probe(
        value.1,
        RuntimeState::Loaded,
        RuntimeState::NotLoaded,
        EvidenceClass::Observed,
        launchd_id,
    );
    let consistency = match (configured, loaded) {
        (Some(a), Some(b)) => Claim::known(
            if a == b {
                ConsistencyState::Consistent
            } else {
                ConsistencyState::Inconsistent
            },
            EvidenceClass::Inferred,
            vec![plist_id, launchd_id],
            unknown_roles(),
        ),
        _ => Claim::unknown(
            UnknownReason::DependentClaimUnknown,
            vec![plist_id, launchd_id],
            unknown_roles(),
        ),
    };
    (configuration, runtime, consistency)
}
fn claim_from_probe<T, U>(
    probe: Probe<T>,
    present: U,
    absent: U,
    class: EvidenceClass,
    id: EvidenceId,
) -> (Claim<U>, Option<bool>) {
    match probe {
        Probe::Observed(_) => (known(present, id, class, unknown_roles()), Some(true)),
        Probe::Absent => (
            known(absent, id, EvidenceClass::Observed, unknown_roles()),
            Some(false),
        ),
        Probe::Unavailable(failure) => (
            Claim::unknown(
                UnknownReason::ProbeFailed(failure),
                vec![id],
                unknown_roles(),
            ),
            None,
        ),
    }
}
