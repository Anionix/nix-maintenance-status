use std::fmt::Debug;

use nix_maintenance_status::{
    Claim, Conclusion, ConfigurationState as Config, ConsistencyState as Consistency,
    DiagnosticInput, EvidenceClass, GcPlist, LaunchdJob, MacOsEvidence, Probe, ProbeFailure,
    RuntimeState as Runtime, UnknownReason, diagnose,
};

fn input(plist: bool, launchd: bool) -> DiagnosticInput {
    let plist = if plist {
        Probe::Observed(GcPlist::new())
    } else {
        Probe::Absent
    };
    let job = if launchd {
        Probe::Observed(LaunchdJob::new())
    } else {
        Probe::Absent
    };
    DiagnosticInput::macos(MacOsEvidence::new(plist, job))
}

#[test]
fn classifies_each_independent_presence_combination() {
    #[rustfmt::skip]
    let cases = [
        (true,  true,  Config::ConsistentWithNixDarwinAutomaticGc, Runtime::Loaded,    Consistency::Consistent),
        (true,  false, Config::ConsistentWithNixDarwinAutomaticGc, Runtime::NotLoaded, Consistency::Inconsistent),
        (false, true,  Config::NotDetected, Runtime::Loaded,    Consistency::Inconsistent),
        (false, false, Config::NotDetected, Runtime::NotLoaded, Consistency::Consistent),
    ];

    for (plist, launchd, configuration, runtime, consistency) in cases {
        let report = diagnose(input(plist, launchd));
        assert_eq!(
            report.configuration().conclusion(),
            &Conclusion::Known(configuration)
        );
        assert_eq!(report.runtime().conclusion(), &Conclusion::Known(runtime));
        assert_eq!(
            report.consistency().conclusion(),
            &Conclusion::Known(consistency)
        );
        assert_eq!(
            report.configuration().provenance().evidence_class(),
            if plist {
                EvidenceClass::Inferred
            } else {
                EvidenceClass::Observed
            }
        );
        assert_eq!(
            report.runtime().provenance().evidence_class(),
            EvidenceClass::Observed
        );
        assert_eq!(
            report.consistency().provenance().evidence_class(),
            EvidenceClass::Inferred
        );
    }
}

fn assert_unknown<T: Debug + PartialEq>(claim: &Claim<T>, reason: UnknownReason) {
    assert_eq!(claim.conclusion(), &Conclusion::Unknown(reason));
    assert_eq!(claim.provenance().evidence_class(), EvidenceClass::Unknown);
}

#[test]
fn unavailable_probes_propagate_unknown_without_erasing_the_independent_claim() {
    let report = diagnose(DiagnosticInput::macos(MacOsEvidence::new(
        Probe::Unavailable(ProbeFailure::FileSystemUnavailable),
        Probe::<LaunchdJob>::Absent,
    )));
    assert_unknown(
        report.configuration(),
        UnknownReason::ProbeFailed(ProbeFailure::FileSystemUnavailable),
    );
    assert_eq!(
        report.runtime().conclusion(),
        &Conclusion::Known(Runtime::NotLoaded)
    );
    assert_unknown(report.consistency(), UnknownReason::DependentClaimUnknown);

    let report = diagnose(DiagnosticInput::macos(MacOsEvidence::new(
        Probe::<GcPlist>::Absent,
        Probe::Unavailable(ProbeFailure::CommandFailed),
    )));
    assert_eq!(
        report.configuration().conclusion(),
        &Conclusion::Known(Config::NotDetected)
    );
    assert_unknown(
        report.runtime(),
        UnknownReason::ProbeFailed(ProbeFailure::CommandFailed),
    );
    assert_unknown(report.consistency(), UnknownReason::DependentClaimUnknown);
}
