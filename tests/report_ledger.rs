use std::time::{Duration, UNIX_EPOCH};

use nix_maintenance_status::{
    DiagnosticInput, GcPlist, LaunchdJob, LedgerError, MacOsEvidence, ObservationComponent,
    Presence, Probe, Provider, ProviderEvidence, ProviderEvidenceSet, ScanScope, ScanWindow,
    Subject, TargetPlatform, build_ledger,
};

fn row(provider: Provider, subject: Subject, component: ObservationComponent) -> ProviderEvidence {
    ProviderEvidence::new(provider, subject, component, Presence::Present).unwrap()
}

fn input(reversed: bool) -> DiagnosticInput {
    let mut rows = vec![
        row(
            Provider::Anacron,
            Subject::System,
            ObservationComponent::Discovery,
        ),
        row(
            Provider::NixOsSystemd,
            Subject::uid(1000),
            ObservationComponent::Discovery,
        ),
    ];
    if reversed {
        rows.reverse();
    }
    let evidence = ProviderEvidenceSet::new(rows).unwrap();
    DiagnosticInput::new(
        TargetPlatform::Linux,
        ScanScope::Default,
        ScanWindow::new(UNIX_EPOCH, Duration::from_secs(1)).unwrap(),
        evidence,
    )
    .unwrap()
}

#[test]
fn ledger_ids_follow_normalized_order_and_are_unique() {
    let ledger = build_ledger(&input(false)).unwrap();
    let values: Vec<_> = ledger.iter().map(|entry| entry.value()).collect();
    assert_eq!(
        values,
        build_ledger(&input(true))
            .unwrap()
            .iter()
            .map(|entry| entry.value())
            .collect::<Vec<_>>()
    );
}

#[test]
fn legacy_input_is_rejected_by_the_new_report_seam() {
    let input = DiagnosticInput::macos(MacOsEvidence::new(
        Probe::Observed(GcPlist::new()),
        Probe::<LaunchdJob>::Absent,
    ));
    assert!(matches!(
        build_ledger(&input),
        Err(LedgerError::LegacyInput)
    ));
}
