use std::time::{Duration, UNIX_EPOCH};

use nix_maintenance_status::{
    CaptureSequence, Conclusion, DefinitionOccurrence, DiagnosticInput, LaunchdCalendarInterval,
    LaunchdDomain, LaunchdField, LaunchdLabel, ObservationComponent, Presence, Provider,
    ProviderEvidence, ProviderEvidenceSet, ProviderLogicalKey, ScanScope, ScanWindow, Schedule,
    SourceOccurrenceKey, SourceRoot, SourceRootId, Subject, TargetPlatform,
};

fn occurrence() -> DefinitionOccurrence {
    DefinitionOccurrence::new(
        ProviderLogicalKey::Launchd {
            domain: LaunchdDomain::System,
            subject: Subject::System,
            label: LaunchdLabel::new("org.nixos.nix-gc").unwrap(),
        },
        SourceOccurrenceKey::new(SourceRoot::LaunchdPlist(SourceRootId::new(1)), 1),
        CaptureSequence::new(0),
    )
}

#[test]
fn launchd_schedule_survives_the_typed_report_boundary() {
    let calendar = LaunchdCalendarInterval::new(
        LaunchdField::Exact(15),
        LaunchdField::Exact(3),
        LaunchdField::Any,
        LaunchdField::Any,
        LaunchdField::Exact(7),
    )
    .unwrap();
    let schedule = Schedule::Launchd(
        nix_maintenance_status::LaunchdSchedule::new(vec![calendar], None, false).unwrap(),
    );
    let row = ProviderEvidence::with_occurrence(
        Provider::NixDarwinLaunchd,
        Subject::System,
        ObservationComponent::Schedule,
        Presence::Present,
        occurrence(),
    )
    .unwrap()
    .with_schedule(schedule)
    .unwrap();
    let input = DiagnosticInput::new(
        TargetPlatform::MacOs,
        ScanScope::System,
        ScanWindow::new(UNIX_EPOCH, Duration::from_secs(1)).unwrap(),
        ProviderEvidenceSet::new(vec![row]).unwrap(),
    )
    .unwrap();
    let report = nix_maintenance_status::diagnose(input);
    let claim = report.automations()[0].claims().schedule();
    assert!(matches!(claim.conclusion(), Conclusion::Known(_)));
    assert_eq!(claim.provenance().evidence_ids().len(), 1);
}

#[test]
fn schedule_payload_is_launchd_only() {
    let schedule = Schedule::Launchd(
        nix_maintenance_status::LaunchdSchedule::new(Vec::new(), Some(60), false).unwrap(),
    );
    let result = ProviderEvidence::new(
        Provider::NixOsSystemd,
        Subject::System,
        ObservationComponent::Schedule,
        Presence::Present,
    )
    .unwrap()
    .with_schedule(schedule);
    assert!(result.is_err());
}
