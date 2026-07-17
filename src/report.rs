use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

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
    pub(crate) fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
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
    pub(crate) fn empty() -> Self {
        Self {
            leaves: Vec::new(),
            aggregate: CoverageAggregate::Unavailable,
        }
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
    consistency: crate::diagnostic::Claim<ObservationValue>,
    schedule: crate::diagnostic::Claim<ObservationValue>,
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
    claim_getters!(
        configuration,
        runtime,
        consistency,
        schedule,
        command,
        activity,
        runs,
        last_result
    );

    pub(crate) fn from_entries(entries: &[&ProviderEvidence], ledger: &EvidenceLedger) -> Self {
        let unknown = || {
            crate::diagnostic::Claim::unknown(
                crate::diagnostic::UnknownReason::DependentClaimUnknown,
            )
        };
        let mut claims = Self {
            configuration: unknown(),
            runtime: unknown(),
            consistency: unknown(),
            schedule: unknown(),
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
            let claim = if conflict {
                crate::diagnostic::Claim::unknown_with_evidence(
                    crate::diagnostic::UnknownReason::EvidenceUnavailable(
                        UnavailableReason::MalformedEvidence,
                    ),
                    ids,
                )
            } else {
                match first {
                    Presence::Absent => {
                        crate::diagnostic::Claim::observed(ObservationValue::Absent, ids)
                    }
                    Presence::PresentEmpty => {
                        crate::diagnostic::Claim::observed(ObservationValue::PresentEmpty, ids)
                    }
                    Presence::Present => {
                        crate::diagnostic::Claim::observed(ObservationValue::Present, ids)
                    }
                    Presence::Unavailable(reason) => {
                        crate::diagnostic::Claim::unavailable(reason, ids)
                    }
                }
            };
            match component {
                ObservationComponent::Configuration => claims.configuration = claim,
                ObservationComponent::Runtime => claims.runtime = claim,
                ObservationComponent::Schedule => claims.schedule = claim,
                ObservationComponent::Command => claims.command = claim,
                ObservationComponent::Activity => claims.activity = claim,
                ObservationComponent::Runs => claims.runs = claim,
                ObservationComponent::LastResult => claims.last_result = claim,
                ObservationComponent::Discovery => unreachable!(),
            }
        }
        claims
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LedgerError {
    LegacyInput,
}

// LLM contract: `build_ledger` only triggers Provider → Subject → component canonicalization with opaque IDs; #44 owns scheduler identity/capture, so rows are not candidates.
// Claims Known/Unknown reject empty/duplicate/reversed/foreign refs; Unknown != Absent; legacy rejected; pure/read-only/offline, no telemetry, and no GC execution.
pub fn build_ledger(input: &DiagnosticInput) -> Result<EvidenceLedger, LedgerError> {
    let evidence = input.evidence().ok_or(LedgerError::LegacyInput)?;
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
    Ok(EvidenceLedger { entries })
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
