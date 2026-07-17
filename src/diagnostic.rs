use crate::catalog::{AuthorityResolution, AuthorityRole};
use crate::evidence::{
    InputError, ProviderEvidenceSet, ScanScope, ScanWindow, TargetPlatform, UnavailableReason,
    validate_input,
};
use crate::report::{
    CoverageMatrix, EvidenceId, EvidenceLedger, GcAutomation, ScanMetadata, build_inventory,
    build_ledger,
};

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
pub struct MacOsEvidence(Probe<GcPlist>, Probe<LaunchdJob>);

impl MacOsEvidence {
    pub fn new(plist: Probe<GcPlist>, launchd: Probe<LaunchdJob>) -> Self {
        Self(plist, launchd)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticInput {
    platform: TargetPlatform,
    scope: ScanScope,
    window: ScanWindow,
    evidence: Option<ProviderEvidenceSet>,
    legacy: Option<MacOsEvidence>,
}

impl DiagnosticInput {
    // LLM contract: `new` is the only generic trigger and accepts only rows
    // already validated by the scope seam; it preserves private normalized
    // Evidence and rejects every validator error without I/O or mutation.
    pub fn new(
        platform: TargetPlatform,
        scope: ScanScope,
        window: ScanWindow,
        evidence: ProviderEvidenceSet,
    ) -> Result<Self, InputError> {
        validate_input(platform, scope, &evidence)?;
        Ok(Self {
            platform,
            scope,
            window,
            evidence: Some(evidence),
            legacy: None,
        })
    }
    pub fn macos(evidence: MacOsEvidence) -> Self {
        Self {
            platform: TargetPlatform::MacOs,
            scope: ScanScope::System,
            window: ScanWindow::new(std::time::UNIX_EPOCH, std::time::Duration::from_secs(1))
                .expect("the fixed legacy window is valid"),
            evidence: None,
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
    pub fn evidence(&self) -> Option<&ProviderEvidenceSet> {
        self.evidence.as_ref()
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
pub enum UnknownReason {
    ProbeFailed(ProbeFailure),
    EvidenceUnavailable(UnavailableReason),
    DependentClaimUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Conclusion<T> {
    Known(T),
    Unknown(UnknownReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    class: EvidenceClass,
    evidence: Vec<EvidenceId>,
    authorities: [AuthorityResolution; 3],
}

impl Provenance {
    pub const fn evidence_class(&self) -> EvidenceClass {
        self.class
    }
    pub fn evidence_ids(&self) -> &[EvidenceId] {
        &self.evidence
    }
    pub const fn authorities(&self) -> &[AuthorityResolution; 3] {
        &self.authorities
    }
    pub const fn authority(&self, role: AuthorityRole) -> AuthorityResolution {
        self.authorities[match role {
            AuthorityRole::GcOperationSemantics => 0,
            AuthorityRole::AutomationMapping => 1,
            AuthorityRole::SchedulerSemantics => 2,
        }]
    }
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

    fn known(value: T, class: EvidenceClass) -> Self {
        Self {
            conclusion: Conclusion::Known(value),
            provenance: Provenance {
                class,
                evidence: Vec::new(),
                authorities: [AuthorityResolution::NotClaimed; 3],
            },
        }
    }

    pub(crate) fn unknown(reason: UnknownReason) -> Self {
        Self {
            conclusion: Conclusion::Unknown(reason),
            provenance: Provenance {
                class: EvidenceClass::Unknown,
                evidence: Vec::new(),
                authorities: [AuthorityResolution::NotClaimed; 3],
            },
        }
    }

    pub(crate) fn observed(value: T, ids: Vec<EvidenceId>) -> Self {
        Self {
            conclusion: Conclusion::Known(value),
            provenance: Provenance {
                class: EvidenceClass::Observed,
                evidence: ids,
                authorities: [AuthorityResolution::NotClaimed; 3],
            },
        }
    }

    pub(crate) fn unavailable(reason: UnavailableReason, ids: Vec<EvidenceId>) -> Self {
        Self {
            conclusion: Conclusion::Unknown(UnknownReason::EvidenceUnavailable(reason)),
            provenance: Provenance {
                class: EvidenceClass::Unknown,
                evidence: ids,
                authorities: [AuthorityResolution::NotClaimed; 3],
            },
        }
    }

    pub(crate) fn unknown_with_evidence(reason: UnknownReason, ids: Vec<EvidenceId>) -> Self {
        Self {
            conclusion: Conclusion::Unknown(reason),
            provenance: Provenance {
                class: EvidenceClass::Unknown,
                evidence: ids,
                authorities: [AuthorityResolution::NotClaimed; 3],
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
pub struct GcReport {
    configuration: Claim<ConfigurationState>,
    runtime: Claim<RuntimeState>,
    consistency: Claim<ConsistencyState>,
    scan: ScanMetadata,
    coverage: CoverageMatrix,
    automations: Vec<GcAutomation>,
    evidence: EvidenceLedger,
}

impl GcReport {
    pub const fn configuration(&self) -> &Claim<ConfigurationState> {
        &self.configuration
    }
    pub const fn runtime(&self) -> &Claim<RuntimeState> {
        &self.runtime
    }
    pub const fn consistency(&self) -> &Claim<ConsistencyState> {
        &self.consistency
    }
    pub const fn scan(&self) -> &ScanMetadata {
        &self.scan
    }
    pub const fn coverage(&self) -> &CoverageMatrix {
        &self.coverage
    }
    pub fn automations(&self) -> &[GcAutomation] {
        &self.automations
    }
    pub const fn evidence(&self) -> &EvidenceLedger {
        &self.evidence
    }
}

// LLM contract: plist and launchd Probes independently become Known for Observed/Absent
// or Unknown for Unavailable. Consistency is Known only when both core Claims are Known;
// equal presence is Consistent. Runtime never changes Configuration; Unknown is not Absent.
// Generic validated input is classified into the immutable inventory boundary;
// legacy MacOsEvidence retains the 0.1 core getters only during the migration
// window and never feeds those getters from generic provider Evidence.
pub fn diagnose(input: DiagnosticInput) -> GcReport {
    let scan = ScanMetadata::new(input.platform(), input.scope(), input.window());
    let Some(legacy) = input.legacy else {
        let evidence = input
            .evidence()
            .expect("validated generic input has evidence");
        let ledger = build_ledger(&input).unwrap_or_else(|_| EvidenceLedger::empty());
        let (automations, coverage) = build_inventory(evidence, &ledger);
        return GcReport {
            configuration: Claim::unknown(UnknownReason::DependentClaimUnknown),
            runtime: Claim::unknown(UnknownReason::DependentClaimUnknown),
            consistency: Claim::unknown(UnknownReason::DependentClaimUnknown),
            scan,
            coverage,
            automations,
            evidence: ledger,
        };
    };
    let (configuration, configured) = claim_from_probe(
        legacy.0,
        ConfigurationState::ConsistentWithNixDarwinAutomaticGc,
        ConfigurationState::NotDetected,
        EvidenceClass::Inferred,
    );
    let (runtime, loaded) = claim_from_probe(
        legacy.1,
        RuntimeState::Loaded,
        RuntimeState::NotLoaded,
        EvidenceClass::Observed,
    );
    let consistency = match (configured, loaded) {
        (Some(configured), Some(loaded)) => Claim::known(
            if configured == loaded {
                ConsistencyState::Consistent
            } else {
                ConsistencyState::Inconsistent
            },
            EvidenceClass::Inferred,
        ),
        _ => Claim::unknown(UnknownReason::DependentClaimUnknown),
    };

    GcReport {
        configuration,
        runtime,
        consistency,
        scan,
        coverage: CoverageMatrix::empty(),
        automations: Vec::new(),
        evidence: EvidenceLedger::empty(),
    }
}

fn claim_from_probe<T, U>(
    probe: Probe<T>,
    present: U,
    absent: U,
    present_class: EvidenceClass,
) -> (Claim<U>, Option<bool>) {
    match probe {
        Probe::Observed(_) => (Claim::known(present, present_class), Some(true)),
        Probe::Absent => (Claim::known(absent, EvidenceClass::Observed), Some(false)),
        Probe::Unavailable(failure) => (Claim::unknown(UnknownReason::ProbeFailed(failure)), None),
    }
}
