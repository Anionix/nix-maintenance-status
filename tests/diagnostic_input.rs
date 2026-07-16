use std::time::{Duration, UNIX_EPOCH};

use nix_maintenance_status::{
    Conclusion, DiagnosticInput, GcPlist, InputError, LaunchdJob, MacOsEvidence,
    ObservationComponent, Presence, Probe, Provider, ProviderEvidence, ProviderEvidenceSet,
    ScanScope, ScanWindow, Subject, TargetPlatform, UnknownReason, diagnose,
};

fn row(subject: Subject) -> ProviderEvidence {
    ProviderEvidence::new(
        Provider::NixOsSystemd,
        subject,
        ObservationComponent::Discovery,
        Presence::Present,
    )
    .unwrap()
}

fn window() -> ScanWindow {
    ScanWindow::new(UNIX_EPOCH, Duration::from_secs(1)).unwrap()
}

#[test]
fn new_exposes_only_validated_normalized_input() {
    let evidence =
        ProviderEvidenceSet::new(vec![row(Subject::System), row(Subject::uid(1000))]).unwrap();
    let input = DiagnosticInput::new(
        TargetPlatform::Linux,
        ScanScope::Default,
        window(),
        evidence,
    )
    .unwrap();
    assert_eq!(input.platform(), TargetPlatform::Linux);
    assert_eq!(input.scope(), ScanScope::Default);
    assert_eq!(input.window().duration(), Duration::from_secs(1));
    assert_eq!(input.evidence().unwrap().entries().len(), 2);
}

#[test]
fn validator_errors_are_returned_without_reinterpretation() {
    let evidence = ProviderEvidenceSet::new(vec![row(Subject::System)]).unwrap();
    assert_eq!(
        DiagnosticInput::new(
            TargetPlatform::Linux,
            ScanScope::Default,
            window(),
            evidence
        ),
        Err(InputError::InvalidScope)
    );
}

#[test]
fn generic_inputs_are_an_explicit_transitional_unknown() {
    let evidence =
        ProviderEvidenceSet::new(vec![row(Subject::System), row(Subject::uid(1000))]).unwrap();
    let report = diagnose(
        DiagnosticInput::new(
            TargetPlatform::Linux,
            ScanScope::Default,
            window(),
            evidence,
        )
        .unwrap(),
    );
    assert_eq!(
        report.configuration().conclusion(),
        &Conclusion::Unknown(UnknownReason::DependentClaimUnknown)
    );
}

#[test]
fn legacy_macos_constructor_remains_compatible() {
    let input = DiagnosticInput::macos(MacOsEvidence::new(
        Probe::Observed(GcPlist::new()),
        Probe::Absent::<LaunchdJob>,
    ));
    assert_eq!(input.platform(), TargetPlatform::MacOs);
    assert!(input.evidence().is_none());
    assert_eq!(
        input,
        DiagnosticInput::macos(MacOsEvidence::new(
            Probe::Observed(GcPlist::new()),
            Probe::<LaunchdJob>::Absent,
        ))
    );
    assert!(matches!(
        diagnose(input).configuration().conclusion(),
        Conclusion::Known(_)
    ));
}
