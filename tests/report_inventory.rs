use std::time::{Duration, UNIX_EPOCH};

use nix_maintenance_status::{
    AuthorityResolution, AuthorityRole, Conclusion, CoverageAggregate, DiagnosticInput,
    EvidenceClass, ObservationComponent, ObservationValue, Presence, Provider, ProviderEvidence,
    ProviderEvidenceSet, ScanScope, ScanWindow, Subject, TargetPlatform, UnavailableReason,
    diagnose,
};

fn input(rows: Vec<ProviderEvidence>) -> DiagnosticInput {
    DiagnosticInput::new(
        TargetPlatform::Linux,
        ScanScope::System,
        ScanWindow::new(UNIX_EPOCH, Duration::from_secs(1)).unwrap(),
        ProviderEvidenceSet::new(rows).unwrap(),
    )
    .unwrap()
}

fn row(component: ObservationComponent, presence: Presence) -> ProviderEvidence {
    ProviderEvidence::new(Provider::NixOsSystemd, Subject::System, component, presence).unwrap()
}

#[test]
fn generic_diagnosis_builds_inventory_and_keeps_unavailable_local() {
    let report = diagnose(input(vec![
        row(ObservationComponent::Configuration, Presence::PresentEmpty),
        row(
            ObservationComponent::Runtime,
            Presence::Unavailable(UnavailableReason::PermissionDenied),
        ),
        row(ObservationComponent::Schedule, Presence::Present),
    ]));

    assert_eq!(report.scan().scope(), ScanScope::System);
    assert_eq!(report.coverage().aggregate(), CoverageAggregate::Partial);
    assert_eq!(report.automations().len(), 1);
    let automation = &report.automations()[0];
    assert_eq!(automation.provider(), Provider::NixOsSystemd);
    assert_eq!(automation.subject(), Subject::System);
    assert_eq!(
        automation
            .claims()
            .configuration()
            .provenance()
            .evidence_class(),
        EvidenceClass::Observed
    );
    assert_eq!(
        automation.claims().configuration().conclusion(),
        &Conclusion::Known(ObservationValue::PresentEmpty)
    );
    assert_eq!(
        automation.claims().runtime().conclusion(),
        &Conclusion::Unknown(nix_maintenance_status::UnknownReason::EvidenceUnavailable(
            UnavailableReason::PermissionDenied
        ))
    );
    assert_eq!(
        automation
            .claims()
            .configuration()
            .provenance()
            .authority(AuthorityRole::AutomationMapping),
        AuthorityResolution::NotClaimed
    );
    assert!(
        !automation
            .claims()
            .configuration()
            .provenance()
            .evidence_ids()
            .is_empty()
    );
}

#[test]
fn absent_and_present_empty_are_covered_observations() {
    let report = diagnose(input(vec![
        row(ObservationComponent::Configuration, Presence::Absent),
        row(ObservationComponent::Runtime, Presence::PresentEmpty),
    ]));
    assert_eq!(report.coverage().aggregate(), CoverageAggregate::Complete);
    let claims = report.automations()[0].claims();
    assert_eq!(
        claims.configuration().conclusion(),
        &Conclusion::Known(ObservationValue::Absent)
    );
    assert_eq!(
        claims.runtime().conclusion(),
        &Conclusion::Known(ObservationValue::PresentEmpty)
    );
}
