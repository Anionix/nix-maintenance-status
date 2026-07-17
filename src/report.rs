use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    time::Duration,
};

use crate::catalog::{AuthorityResolution, AuthorityUnknownReason};
use crate::diagnostic::{DiagnosticInput, EvidenceClass};
use crate::evidence::{
    ObservationComponent, Presence, Provider, ProviderEvidence, ProviderEvidenceSet, ScanScope,
    ScanWindow, Subject, TargetPlatform, UnavailableReason,
};

#[derive(Clone, PartialEq, Eq)]
pub struct EvidenceId(usize);

impl fmt::Debug for EvidenceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EvidenceId(<opaque>)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportEvidence {
    id: EvidenceId,
    value: ProviderEvidence,
}

impl ReportEvidence {
    pub fn id(&self) -> EvidenceId {
        self.id.clone()
    }
    pub const fn value(&self) -> &ProviderEvidence {
        &self.value
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceLedger {
    entries: Vec<ReportEvidence>,
}

impl EvidenceLedger {
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = &ReportEvidence> + '_ {
        self.entries.iter()
    }
    pub(crate) fn owns(&self, evidence: &ReportEvidence) -> bool {
        self.entries
            .iter()
            .any(|entry| std::ptr::eq(entry, evidence))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanMetadata {
    platform: TargetPlatform,
    scope: ScanScope,
    window: ScanWindow,
}

impl ScanMetadata {
    pub const fn platform(&self) -> TargetPlatform {
        self.platform
    }
    pub const fn scope(&self) -> ScanScope {
        self.scope
    }
    pub const fn window(&self) -> ScanWindow {
        self.window
    }
    pub(crate) const fn new(
        platform: TargetPlatform,
        scope: ScanScope,
        window: ScanWindow,
    ) -> Self {
        Self {
            platform,
            scope,
            window,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObservationValue {
    Absent,
    PresentEmpty,
    Present,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum LaunchdField<T> {
    Any,
    Exact(T),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LaunchdCalendarInterval {
    minute: LaunchdField<u8>,
    hour: LaunchdField<u8>,
    day: LaunchdField<u8>,
    month: LaunchdField<u8>,
    weekday: LaunchdField<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ScheduleError {
    Empty,
    InvalidRange,
    ZeroInterval,
}

impl LaunchdCalendarInterval {
    pub fn new(
        minute: LaunchdField<u8>,
        hour: LaunchdField<u8>,
        day: LaunchdField<u8>,
        month: LaunchdField<u8>,
        weekday: LaunchdField<u8>,
    ) -> Result<Self, ScheduleError> {
        let valid = |field, max| match field {
            LaunchdField::Any => true,
            LaunchdField::Exact(value) => value <= max,
        };
        if !valid(minute, 59)
            || !valid(hour, 23)
            || !valid(day, 31)
            || !valid(month, 12)
            || !valid(weekday, 7)
        {
            return Err(ScheduleError::InvalidRange);
        }
        Ok(Self {
            minute,
            hour,
            day,
            month,
            weekday: match weekday {
                LaunchdField::Exact(7) => LaunchdField::Exact(0),
                other => other,
            },
        })
    }
    pub const fn minute(&self) -> LaunchdField<u8> {
        self.minute
    }
    pub const fn hour(&self) -> LaunchdField<u8> {
        self.hour
    }
    pub const fn day(&self) -> LaunchdField<u8> {
        self.day
    }
    pub const fn month(&self) -> LaunchdField<u8> {
        self.month
    }
    pub const fn weekday(&self) -> LaunchdField<u8> {
        self.weekday
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LaunchdSchedule {
    calendar: Vec<LaunchdCalendarInterval>,
    interval_seconds: Option<u64>,
    run_at_load: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum SystemdTrigger {
    OnCalendar(String),
    OnActiveSec(Duration),
    OnBootSec(Duration),
    OnStartupSec(Duration),
    OnUnitActiveSec(Duration),
    OnUnitInactiveSec(Duration),
    OnClockChange,
    OnTimezoneChange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SystemdTimerPolicy {
    accuracy: Option<Duration>,
    randomized_delay: Option<Duration>,
    fixed_random_delay: bool,
    randomized_offset: Option<Duration>,
    defer_reactivation: bool,
    persistent: bool,
    wake_system: bool,
}

impl SystemdTimerPolicy {
    pub const fn new(
        accuracy: Option<Duration>,
        randomized_delay: Option<Duration>,
        fixed_random_delay: bool,
        randomized_offset: Option<Duration>,
        defer_reactivation: bool,
        persistent: bool,
        wake_system: bool,
    ) -> Self {
        Self {
            accuracy,
            randomized_delay,
            fixed_random_delay,
            randomized_offset,
            defer_reactivation,
            persistent,
            wake_system,
        }
    }
    pub const fn accuracy(&self) -> Option<Duration> {
        self.accuracy
    }
    pub const fn randomized_delay(&self) -> Option<Duration> {
        self.randomized_delay
    }
    pub const fn fixed_random_delay(&self) -> bool {
        self.fixed_random_delay
    }
    pub const fn randomized_offset(&self) -> Option<Duration> {
        self.randomized_offset
    }
    pub const fn defer_reactivation(&self) -> bool {
        self.defer_reactivation
    }
    pub const fn persistent(&self) -> bool {
        self.persistent
    }
    pub const fn wake_system(&self) -> bool {
        self.wake_system
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SystemdSchedule {
    triggers: Vec<SystemdTrigger>,
    policy: SystemdTimerPolicy,
}

impl SystemdSchedule {
    pub fn new(
        triggers: Vec<SystemdTrigger>,
        policy: SystemdTimerPolicy,
    ) -> Result<Self, ScheduleError> {
        if triggers.is_empty() {
            return Err(ScheduleError::Empty);
        }
        if triggers.iter().any(|trigger| {
            matches!(trigger, SystemdTrigger::OnCalendar(expression)
                if expression.is_empty()
                    || expression.len() > 256
                    || expression.chars().any(char::is_control))
        }) {
            return Err(ScheduleError::InvalidRange);
        }
        Ok(Self { triggers, policy })
    }
    pub fn triggers(&self) -> &[SystemdTrigger] {
        &self.triggers
    }
    pub const fn policy(&self) -> &SystemdTimerPolicy {
        &self.policy
    }
}

impl LaunchdSchedule {
    pub fn new(
        calendar: Vec<LaunchdCalendarInterval>,
        interval_seconds: Option<u64>,
        run_at_load: bool,
    ) -> Result<Self, ScheduleError> {
        if calendar.is_empty() && interval_seconds.is_none() && !run_at_load {
            return Err(ScheduleError::Empty);
        }
        if interval_seconds == Some(0) {
            return Err(ScheduleError::ZeroInterval);
        }
        Ok(Self {
            calendar,
            interval_seconds,
            run_at_load,
        })
    }
    pub fn calendar(&self) -> &[LaunchdCalendarInterval] {
        &self.calendar
    }
    pub const fn interval_seconds(&self) -> Option<u64> {
        self.interval_seconds
    }
    pub const fn run_at_load(&self) -> bool {
        self.run_at_load
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Schedule {
    Launchd(LaunchdSchedule),
    Systemd(SystemdSchedule),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ConsistencyValue {
    Consistent,
    Inconsistent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CoverageStatus {
    Covered,
    Unavailable(UnavailableReason),
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CoverageAggregate {
    Complete,
    Partial,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CoverageLeaf {
    provider: Provider,
    subject: Subject,
    component: ObservationComponent,
    status: CoverageStatus,
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
    pub const fn status(&self) -> CoverageStatus {
        self.status
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageMatrix {
    leaves: Vec<CoverageLeaf>,
    aggregate: CoverageAggregate,
}

impl CoverageMatrix {
    pub fn leaves(&self) -> &[CoverageLeaf] {
        &self.leaves
    }
    pub const fn aggregate(&self) -> CoverageAggregate {
        self.aggregate
    }
    pub(crate) fn from_evidence(evidence: &ProviderEvidenceSet) -> Self {
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
        let coordinates: BTreeSet<_> = evidence
            .entries()
            .iter()
            .map(|entry| (entry.provider(), entry.subject()))
            .collect();
        let leaves = coordinates
            .into_iter()
            .flat_map(|(provider, subject)| {
                COMPONENTS.into_iter().map(move |component| {
                    let mut observed = false;
                    let mut unavailable = None;
                    for row in evidence.entries().iter().filter(|entry| {
                        entry.provider() == provider
                            && entry.subject() == subject
                            && entry.component() == component
                    }) {
                        match row.presence() {
                            Presence::Unavailable(reason) => unavailable = Some(reason),
                            Presence::Absent | Presence::PresentEmpty | Presence::Present => {
                                observed = true
                            }
                        }
                    }
                    CoverageLeaf {
                        provider,
                        subject,
                        component,
                        status: unavailable.map_or_else(
                            || {
                                if observed {
                                    CoverageStatus::Covered
                                } else {
                                    CoverageStatus::Unavailable(
                                        UnavailableReason::InterfaceUnavailable,
                                    )
                                }
                            },
                            CoverageStatus::Unavailable,
                        ),
                    }
                })
            })
            .collect::<Vec<_>>();
        let covered = leaves
            .iter()
            .filter(|leaf| leaf.status == CoverageStatus::Covered)
            .count();
        let unavailable = leaves
            .iter()
            .filter(|leaf| matches!(leaf.status, CoverageStatus::Unavailable(_)))
            .count();
        let aggregate = match (covered, unavailable) {
            (0, 0) => CoverageAggregate::Unavailable,
            (0, _) => CoverageAggregate::Unavailable,
            (_, 0) => CoverageAggregate::Complete,
            _ => CoverageAggregate::Partial,
        };
        Self { leaves, aggregate }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AutomationId(u32);

impl fmt::Debug for AutomationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AutomationId(<opaque>)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutomationClaims {
    configuration: crate::diagnostic::Claim<ObservationValue>,
    runtime: crate::diagnostic::Claim<ObservationValue>,
    consistency: crate::diagnostic::Claim<ConsistencyValue>,
    schedule: crate::diagnostic::Claim<Schedule>,
    command: crate::diagnostic::Claim<ObservationValue>,
    activity: crate::diagnostic::Claim<ObservationValue>,
    runs: crate::diagnostic::Claim<ObservationValue>,
    last_result: crate::diagnostic::Claim<ObservationValue>,
}

macro_rules! claim_getters {
    ($($name:ident),+ $(,)?) => {
        $(
        pub const fn $name(&self) -> &crate::diagnostic::Claim<ObservationValue> {
            &self.$name
        }
        )+
    };
}

impl AutomationClaims {
    claim_getters!(configuration, runtime, command, activity, runs, last_result);

    pub const fn consistency(&self) -> &crate::diagnostic::Claim<ConsistencyValue> {
        &self.consistency
    }
    pub const fn schedule(&self) -> &crate::diagnostic::Claim<Schedule> {
        &self.schedule
    }

    // LLM contract: normalized rows carry matching role results; disagreement
    // is unresolved and missing schedule payload keeps evidence/provenance.
    pub(crate) fn from_entries(entries: &[&ProviderEvidence], ledger: &EvidenceLedger) -> Self {
        let unknown = || {
            crate::diagnostic::Claim::unknown(
                crate::diagnostic::UnknownReason::DependentClaimUnknown,
            )
        };
        let mut claims = Self {
            configuration: unknown(),
            runtime: unknown(),
            consistency: crate::diagnostic::Claim::unknown(
                crate::diagnostic::UnknownReason::DependentClaimUnknown,
            ),
            schedule: crate::diagnostic::Claim::unknown(
                crate::diagnostic::UnknownReason::DependentClaimUnknown,
            ),
            command: unknown(),
            activity: unknown(),
            runs: unknown(),
            last_result: unknown(),
        };
        for component in [
            ObservationComponent::Configuration,
            ObservationComponent::Runtime,
            ObservationComponent::Schedule,
            ObservationComponent::Command,
            ObservationComponent::Activity,
            ObservationComponent::Runs,
            ObservationComponent::LastResult,
        ] {
            let component_entries: Vec<_> = entries
                .iter()
                .copied()
                .filter(|entry| entry.component() == component)
                .collect();
            if component_entries.is_empty() {
                continue;
            }
            let ids = component_entries
                .iter()
                .filter_map(|entry| ledger.id_for(entry))
                .collect::<Vec<_>>();
            let first = component_entries[0].presence();
            let conflict = component_entries
                .iter()
                .any(|entry| entry.presence() != first);
            let authorities = merge_authorities(&component_entries);
            let claim = if conflict {
                unknown_claim(
                    crate::diagnostic::UnknownReason::EvidenceUnavailable(
                        UnavailableReason::MalformedEvidence,
                    ),
                    ids.clone(),
                    authorities,
                )
            } else {
                presence_claim(first, ids.clone(), authorities)
            };
            match component {
                ObservationComponent::Configuration => claims.configuration = claim,
                ObservationComponent::Runtime => claims.runtime = claim,
                ObservationComponent::Schedule => {
                    let schedule = component_entries.iter().find_map(|entry| entry.schedule());
                    claims.schedule = match (schedule, conflict) {
                        (Some(schedule), false) => crate::diagnostic::Claim::from_parts(
                            crate::diagnostic::Conclusion::Known(schedule.clone()),
                            EvidenceClass::Observed,
                            ids,
                            authorities,
                        ),
                        _ => unknown_claim(
                            if conflict {
                                crate::diagnostic::UnknownReason::EvidenceUnavailable(
                                    UnavailableReason::MalformedEvidence,
                                )
                            } else if let Presence::Unavailable(reason) = first {
                                crate::diagnostic::UnknownReason::EvidenceUnavailable(reason)
                            } else {
                                crate::diagnostic::UnknownReason::DependentClaimUnknown
                            },
                            ids,
                            authorities,
                        ),
                    };
                }
                ObservationComponent::Command => claims.command = claim,
                ObservationComponent::Activity => claims.activity = claim,
                ObservationComponent::Runs => claims.runs = claim,
                ObservationComponent::LastResult => claims.last_result = claim,
                ObservationComponent::Discovery => unreachable!(),
            }
        }
        let configuration = match claims.configuration.conclusion() {
            crate::diagnostic::Conclusion::Known(value) => Some(value),
            crate::diagnostic::Conclusion::Unknown(_) => None,
        };
        let runtime = match claims.runtime.conclusion() {
            crate::diagnostic::Conclusion::Known(value) => Some(value),
            crate::diagnostic::Conclusion::Unknown(_) => None,
        };
        if let (Some(configuration), Some(runtime)) = (configuration, runtime) {
            let ids = claims
                .configuration
                .provenance()
                .evidence_ids()
                .iter()
                .chain(claims.runtime.provenance().evidence_ids())
                .cloned()
                .collect();
            let configuration_present = matches!(
                configuration,
                ObservationValue::Present | ObservationValue::PresentEmpty
            );
            let runtime_present = matches!(
                runtime,
                ObservationValue::Present | ObservationValue::PresentEmpty
            );
            let authorities = merge_claim_authorities(&[
                claims.configuration.authorities(),
                claims.runtime.authorities(),
            ]);
            claims.consistency = crate::diagnostic::Claim::from_parts(
                crate::diagnostic::Conclusion::Known(if configuration_present == runtime_present {
                    ConsistencyValue::Consistent
                } else {
                    ConsistencyValue::Inconsistent
                }),
                EvidenceClass::Inferred,
                ids,
                authorities,
            );
        }
        claims
    }
}

fn unknown_claim<T>(
    // LLM contract: Unknown remains terminal for this component and retains
    // only normalized evidence and adapter authority; it never infers value.
    reason: crate::diagnostic::UnknownReason,
    ids: Vec<EvidenceId>,
    authorities: [AuthorityResolution; 3],
) -> crate::diagnostic::Claim<T> {
    crate::diagnostic::Claim::from_parts(
        crate::diagnostic::Conclusion::Unknown(reason),
        EvidenceClass::Unknown,
        ids,
        authorities,
    )
}

fn presence_claim(
    // LLM contract: Absent/Present are observed; Unavailable is Unknown, and
    // no branch performs I/O or changes the supplied authority.
    presence: Presence,
    ids: Vec<EvidenceId>,
    authorities: [AuthorityResolution; 3],
) -> crate::diagnostic::Claim<ObservationValue> {
    let value = match presence {
        Presence::Absent => Some(ObservationValue::Absent),
        Presence::PresentEmpty => Some(ObservationValue::PresentEmpty),
        Presence::Present => Some(ObservationValue::Present),
        Presence::Unavailable(_) => None,
    };
    match value {
        None => unknown_claim(
            crate::diagnostic::UnknownReason::EvidenceUnavailable(match presence {
                Presence::Unavailable(reason) => reason,
                _ => unreachable!(),
            }),
            ids,
            authorities,
        ),
        Some(value) => crate::diagnostic::Claim::from_parts(
            crate::diagnostic::Conclusion::Known(value),
            EvidenceClass::Observed,
            ids,
            authorities,
        ),
    }
}

fn merge_authorities(entries: &[&ProviderEvidence]) -> [AuthorityResolution; 3] {
    merge_claim_authorities(
        &entries
            .iter()
            .map(|entry| entry.authorities())
            .collect::<Vec<_>>(),
    )
}

fn merge_claim_authorities(values: &[&[AuthorityResolution; 3]]) -> [AuthorityResolution; 3] {
    // LLM contract: identical role results survive; any disagreement,
    // including NotClaimed versus a result, becomes unresolved.
    let mut merged = [AuthorityResolution::NotClaimed; 3];
    for index in 0..3 {
        let Some(first) = values.first().map(|value| value[index]) else {
            continue;
        };
        merged[index] = if values.iter().all(|value| value[index] == first) {
            first
        } else {
            AuthorityResolution::Unresolved(AuthorityUnknownReason::ExactBasisUnverifiable)
        };
    }
    merged
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcAutomation {
    id: AutomationId,
    subject: Subject,
    provider: Provider,
    claims: AutomationClaims,
}

impl GcAutomation {
    pub const fn id(&self) -> &AutomationId {
        &self.id
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

// LLM contract: `build_ledger` only triggers Provider → Subject → component
// canonicalization with opaque IDs; identity-free rows remain evidence and
// never become candidates.
// Claims Known/Unknown reject empty/duplicate/reversed/foreign refs; Unknown != Absent; pure/read-only/offline, no telemetry, and no GC execution.
pub fn build_ledger(input: &DiagnosticInput) -> EvidenceLedger {
    let evidence = input.evidence();
    let mut values = evidence.entries().to_vec();
    values.sort_by_key(|value| {
        (
            value.provider().catalog_order(),
            value.subject(),
            value.component(),
            value.occurrence().cloned(),
            value.presence(),
        )
    });
    let entries = values
        .into_iter()
        .enumerate()
        .map(|(ordinal, value)| ReportEvidence {
            id: EvidenceId(ordinal),
            value,
        })
        .collect();
    EvidenceLedger { entries }
}

impl EvidenceLedger {
    fn id_for(&self, value: &ProviderEvidence) -> Option<EvidenceId> {
        self.entries
            .iter()
            .find(|entry| entry.value() == value)
            .map(ReportEvidence::id)
    }
}

// LLM contract: generic Evidence is the sole trigger for inventory rows. Only
// rows with a validated provider occurrence become candidates; identity-free
// rows remain ledger/Coverage evidence. Rows are grouped by the normalized
// provider/subject/occurrence key; conflicting Presence values become local
// Unknown. Sorting is canonical and this function performs no I/O, network,
// mutation, telemetry, scheduler operation, or GC execution.
pub(crate) fn build_inventory(
    evidence: &ProviderEvidenceSet,
    ledger: &EvidenceLedger,
) -> (Vec<GcAutomation>, CoverageMatrix) {
    let mut groups: BTreeMap<
        (
            Provider,
            Subject,
            Option<crate::evidence::DefinitionOccurrence>,
        ),
        Vec<&ProviderEvidence>,
    > = BTreeMap::new();
    for entry in evidence
        .entries()
        .iter()
        .filter(|entry| entry.occurrence().is_some())
    {
        groups
            .entry((
                entry.provider(),
                entry.subject(),
                entry.occurrence().cloned(),
            ))
            .or_default()
            .push(entry);
    }
    let automations = groups
        .into_iter()
        .enumerate()
        .map(
            |(ordinal, ((provider, subject, _), entries))| GcAutomation {
                id: AutomationId(ordinal as u32),
                subject,
                provider,
                claims: AutomationClaims::from_entries(&entries, ledger),
            },
        )
        .collect();
    (automations, CoverageMatrix::from_evidence(evidence))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReportUnknown {
    MissingEvidence,
    DependentClaimUnknown,
}

#[derive(Debug, Clone)]
pub struct ReportProvenance {
    class: EvidenceClass,
    evidence: Vec<EvidenceId>,
}

impl ReportProvenance {
    pub const fn evidence_class(&self) -> EvidenceClass {
        self.class
    }
    pub fn evidence_ids(&self) -> &[EvidenceId] {
        &self.evidence
    }

    fn from_evidence(
        class: EvidenceClass,
        ledger: &EvidenceLedger,
        evidence: &[&ReportEvidence],
    ) -> Option<Self> {
        if evidence.is_empty() || evidence.iter().any(|entry| !ledger.owns(entry)) {
            return None;
        }
        let ids: Vec<_> = evidence.iter().map(|entry| entry.id.clone()).collect();
        if ids.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return None;
        }
        Some(Self {
            class,
            evidence: ids,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportConclusion<T> {
    Known(T),
    Unknown(ReportUnknown),
}

#[derive(Debug, Clone)]
pub struct ReportClaim<T> {
    conclusion: ReportConclusion<T>,
    provenance: ReportProvenance,
}

impl<T> ReportClaim<T> {
    pub const fn conclusion(&self) -> &ReportConclusion<T> {
        &self.conclusion
    }
    pub const fn provenance(&self) -> &ReportProvenance {
        &self.provenance
    }
    // Constructors consume ledger-owned evidence tokens, never caller IDs.
    #[allow(dead_code)] // consumed by the classifier slice
    pub(crate) fn known(
        value: T,
        ledger: &EvidenceLedger,
        evidence: &[&ReportEvidence],
    ) -> Option<Self> {
        Self::known_with_class(value, EvidenceClass::Observed, ledger, evidence)
    }
    #[allow(dead_code)] // consumed by the classifier slice
    pub(crate) fn known_with_class(
        value: T,
        class: EvidenceClass,
        ledger: &EvidenceLedger,
        evidence: &[&ReportEvidence],
    ) -> Option<Self> {
        Some(Self {
            conclusion: ReportConclusion::Known(value),
            provenance: ReportProvenance::from_evidence(class, ledger, evidence)?,
        })
    }
    #[allow(dead_code)] // consumed by the classifier slice
    pub(crate) fn unknown(
        reason: ReportUnknown,
        ledger: &EvidenceLedger,
        evidence: &[&ReportEvidence],
    ) -> Option<Self> {
        Some(Self {
            conclusion: ReportConclusion::Unknown(reason),
            provenance: ReportProvenance::from_evidence(EvidenceClass::Unknown, ledger, evidence)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{ObservationComponent, Presence, Provider, Subject, UnavailableReason};

    #[test]
    fn claims_keep_value_and_evidence_provenance() {
        let unavailable = ReportEvidence {
            id: EvidenceId(5),
            value: ProviderEvidence::new(
                Provider::NixDarwinLaunchd,
                Subject::System,
                ObservationComponent::Configuration,
                Presence::Unavailable(UnavailableReason::InterfaceUnavailable),
            )
            .unwrap(),
        };
        let ledger = EvidenceLedger {
            entries: vec![
                ReportEvidence {
                    id: EvidenceId(4),
                    value: ProviderEvidence::new(
                        Provider::NixDarwinLaunchd,
                        Subject::System,
                        ObservationComponent::Runtime,
                        Presence::Present,
                    )
                    .unwrap(),
                },
                unavailable,
            ],
        };
        let entries: Vec<_> = ledger.iter().collect();
        let evidence = entries[0];
        assert_eq!(format!("{:?}", evidence.id()), "EvidenceId(<opaque>)");
        assert!(!format!("{:?}", ledger).contains("EvidenceId(4)"));
        let known = ReportClaim::known("loaded", &ledger, &[evidence]).unwrap();
        assert_eq!(known.provenance().evidence_ids().len(), 1);
        assert!(matches!(
            known.conclusion(),
            ReportConclusion::Known("loaded")
        ));
        let inferred =
            ReportClaim::known_with_class("mapped", EvidenceClass::Inferred, &ledger, &[evidence])
                .unwrap();
        assert_eq!(
            inferred.provenance().evidence_class(),
            EvidenceClass::Inferred
        );
        let unknown: ReportClaim<()> =
            ReportClaim::unknown(ReportUnknown::MissingEvidence, &ledger, &[entries[1]]).unwrap();
        assert!(matches!(
            unknown.conclusion(),
            ReportConclusion::Unknown(ReportUnknown::MissingEvidence)
        ));
        let copied = (*evidence).clone();
        assert!(ReportClaim::known("copied", &ledger, &[&copied]).is_none());
        assert!(ReportClaim::known("empty", &ledger, &[]).is_none());
        assert!(ReportClaim::known("reversed", &ledger, &[entries[1], entries[0]]).is_none());
    }
}
