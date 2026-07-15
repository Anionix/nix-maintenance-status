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
pub struct DiagnosticInput(MacOsEvidence);

impl DiagnosticInput {
    pub fn macos(evidence: MacOsEvidence) -> Self {
        Self(evidence)
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
    DependentClaimUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Conclusion<T> {
    Known(T),
    Unknown(UnknownReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Provenance(EvidenceClass);

impl Provenance {
    pub const fn evidence_class(&self) -> EvidenceClass {
        self.0
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
            provenance: Provenance(class),
        }
    }

    fn unknown(reason: UnknownReason) -> Self {
        Self {
            conclusion: Conclusion::Unknown(reason),
            provenance: Provenance(EvidenceClass::Unknown),
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
}

// LLM contract: plist and launchd Probes independently become Known for Observed/Absent
// or Unknown for Unavailable. Consistency is Known only when both core Claims are Known;
// equal presence is Consistent. Runtime never changes Configuration; Unknown is not Absent.
pub fn diagnose(input: DiagnosticInput) -> GcReport {
    let evidence = input.0;
    let (configuration, configured) = claim_from_probe(
        evidence.0,
        ConfigurationState::ConsistentWithNixDarwinAutomaticGc,
        ConfigurationState::NotDetected,
        EvidenceClass::Inferred,
    );
    let (runtime, loaded) = claim_from_probe(
        evidence.1,
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
