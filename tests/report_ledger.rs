use std::time::{Duration, UNIX_EPOCH};

use nix_maintenance_status::{
    DiagnosticInput, ObservationComponent, Presence, Provider, ProviderEvidence,
    ProviderEvidenceSet, ScanScope, ScanWindow, Subject, TargetPlatform, build_ledger,
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
    DiagnosticInput::new(
        TargetPlatform::Linux,
        ScanScope::Default,
        ScanWindow::new(UNIX_EPOCH, Duration::from_secs(1)).unwrap(),
        ProviderEvidenceSet::new(rows).unwrap(),
    )
    .unwrap()
}

#[test]
fn ledger_ids_follow_normalized_order_and_are_unique() {
    let ledger = build_ledger(&input(false));
    let values: Vec<_> = ledger.iter().map(|entry| entry.value()).collect();
    assert_eq!(
        values,
        build_ledger(&input(true))
            .iter()
            .map(|entry| entry.value())
            .collect::<Vec<_>>()
    );
    assert_eq!(ledger.len(), 2);
}
