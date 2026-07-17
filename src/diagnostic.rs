use crate::catalog::{AuthorityResolution, AuthorityRole};
use crate::evidence::{
    InputError, ProviderEvidenceSet, ScanScope, ScanWindow, TargetPlatform, UnavailableReason,
    validate_input,
};
use crate::report::{
    CoverageMatrix, EvidenceId, EvidenceLedger, GcAutomation, ScanMetadata, build_inventory,
    build_ledger,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticInput {
    platform: TargetPlatform,
    scope: ScanScope,
    window: ScanWindow,
    evidence: ProviderEvidenceSet,
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
            evidence,
        })
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
    pub const fn evidence(&self) -> &ProviderEvidenceSet {
        &self.evidence
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

    pub(crate) fn inferred(value: T, ids: Vec<EvidenceId>) -> Self {
        Self {
            conclusion: Conclusion::Known(value),
            provenance: Provenance {
                class: EvidenceClass::Inferred,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcReport {
    scan: ScanMetadata,
    coverage: CoverageMatrix,
    automations: Vec<GcAutomation>,
    evidence: EvidenceLedger,
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
    pub const fn evidence(&self) -> &EvidenceLedger {
        &self.evidence
    }
}

// LLM contract: validated Provider Evidence is the only diagnose trigger.
// Evidence becomes immutable ordered inventory/Coverage; Unavailable remains
// local Unknown and no adapter fallback, I/O, network, mutation, telemetry,
// scheduler operation, or GC execution occurs in classification.
pub fn diagnose(input: DiagnosticInput) -> GcReport {
    let scan = ScanMetadata::new(input.platform(), input.scope(), input.window());
    let ledger = build_ledger(&input);
    let (automations, coverage) = build_inventory(input.evidence(), &ledger);
    GcReport {
        scan,
        coverage,
        automations,
        evidence: ledger,
    }
}
