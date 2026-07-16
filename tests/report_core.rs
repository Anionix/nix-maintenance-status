use std::time::{Duration, UNIX_EPOCH};

use nix_maintenance_status::{
    Conclusion, CoverageStatus, DiagnosticInput, EvidenceClass, GcPlist, LaunchdJob, MacOsEvidence,
    ObservationComponent, Presence, Probe, Provider, ProviderEvidence, ProviderEvidenceSet,
    RuntimeState, ScanScope, ScanWindow, Subject, TargetPlatform, UnavailableReason, UnknownReason,
    diagnose,
};

fn input(values: Vec<ProviderEvidence>) -> DiagnosticInput {
    DiagnosticInput::new(
        TargetPlatform::Linux,
        ScanScope::Default,
        ScanWindow::new(UNIX_EPOCH + Duration::from_secs(1), Duration::from_secs(1)).unwrap(),
        ProviderEvidenceSet::new(values).unwrap(),
    )
    .unwrap()
}

#[test]
fn component_evidence_is_independent_and_missing_provider_leaves_are_unavailable() {
    let report = diagnose(input(vec![
        ProviderEvidence::new(
            Provider::NixOsSystemd,
            Subject::System,
            ObservationComponent::Discovery,
            Presence::Present,
        )
        .unwrap(),
        ProviderEvidence::new(
            Provider::NixOsSystemd,
            Subject::System,
            ObservationComponent::Runtime,
            Presence::Present,
        )
        .unwrap(),
    ]));
    assert_eq!(report.coverage().status(), CoverageStatus::Partial);
    assert_eq!(report.automations().len(), 1);
    assert_eq!(
        report.automations()[0].claims().runtime().conclusion(),
        &Conclusion::Known(RuntimeState::Loaded)
    );
    assert_eq!(
        report.automations()[0]
            .claims()
            .runtime()
            .provenance()
            .evidence_ids()
            .len(),
        1
    );
    let runtime_id = report
        .evidence()
        .iter()
        .find(|(_, evidence)| {
            matches!(
                evidence,
                nix_maintenance_status::Evidence::Observation {
                    component: ObservationComponent::Runtime,
                    ..
                }
            )
        })
        .map(|(id, _)| id)
        .unwrap();
    assert_eq!(
        report.automations()[0]
            .claims()
            .runtime()
            .provenance()
            .evidence_ids(),
        &[runtime_id]
    );
    assert_eq!(
        report.automations()[0]
            .claims()
            .configuration()
            .provenance()
            .evidence_class(),
        EvidenceClass::Unknown
    );
    assert!(report.coverage().leaves().iter().any(|leaf| {
        leaf.provider() == Provider::Cronie
            && matches!(
                leaf.status(),
                nix_maintenance_status::CoverageLeafStatus::Unavailable(_)
            )
    }));
}

#[test]
fn absent_and_unavailable_are_not_collapsed() {
    let absent = diagnose(input(vec![
        ProviderEvidence::new(
            Provider::NixOsSystemd,
            Subject::System,
            ObservationComponent::Discovery,
            Presence::Absent,
        )
        .unwrap(),
    ]));
    assert_eq!(absent.coverage().status(), CoverageStatus::Partial);
    let unavailable = diagnose(input(vec![
        ProviderEvidence::new(
            Provider::NixOsSystemd,
            Subject::System,
            ObservationComponent::Discovery,
            Presence::Unavailable(UnavailableReason::PermissionDenied),
        )
        .unwrap(),
    ]));
    assert!(unavailable.coverage().leaves().iter().any(|leaf| {
        matches!(
            leaf.status(),
            nix_maintenance_status::CoverageLeafStatus::Unavailable(
                UnavailableReason::PermissionDenied
            )
        )
    }));
}

#[test]
fn legacy_mac_os_claims_keep_configuration_and_runtime_evidence_ids() {
    let report = diagnose(DiagnosticInput::macos(MacOsEvidence::new(
        Probe::Observed(GcPlist::new()),
        Probe::Observed(LaunchdJob::new()),
    )));
    assert_eq!(report.evidence().len(), 3);
    assert_eq!(report.configuration().provenance().evidence_ids().len(), 1);
    assert_eq!(report.runtime().provenance().evidence_ids().len(), 1);
    assert_eq!(report.consistency().provenance().evidence_ids().len(), 2);
    assert!(matches!(
        report.automations()[0]
            .claims()
            .configuration()
            .conclusion(),
        Conclusion::Unknown(UnknownReason::Authority(_))
    ));
}
