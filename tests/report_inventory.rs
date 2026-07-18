use std::time::{Duration, UNIX_EPOCH};

use nix_maintenance_status::{
    AuthorityResolution, AuthorityRole, CaptureSequence, Conclusion, CoverageAggregate,
    DefinitionOccurrence, DiagnosticInput, EvidenceClass, ObservationComponent,
    ObservationUnknownReason, ObservationValue, Presence, Provider, ProviderEvidence,
    ProviderEvidenceSet, ProviderLogicalKey, ScanScope, ScanWindow, SourceOccurrenceKey,
    SourceRoot, SourceRootId, Subject, SystemdManagerIdentity, SystemdUnitId, TargetPlatform,
    UnavailableReason, diagnose,
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
    ProviderEvidence::with_occurrence(
        Provider::NixOsSystemd,
        Subject::System,
        component,
        presence,
        occurrence(),
    )
    .unwrap()
}

fn occurrence() -> DefinitionOccurrence {
    systemd_occurrence(1, 1, 0)
}

fn systemd_occurrence(source_id: u32, ordinal: u32, capture: u32) -> DefinitionOccurrence {
    DefinitionOccurrence::new(
        ProviderLogicalKey::Systemd {
            manager: SystemdManagerIdentity::System,
            subject: Subject::System,
            canonical_timer_id: SystemdUnitId::new("nix-gc.timer").unwrap(),
        },
        SourceOccurrenceKey::new(
            SourceRoot::SystemdUnit(SourceRootId::new(source_id)),
            ordinal,
        ),
        CaptureSequence::new(capture),
    )
}

fn anonymous_occurrence(source_id: u32, ordinal: u32, capture: u32) -> DefinitionOccurrence {
    DefinitionOccurrence::new(
        ProviderLogicalKey::Anonymous,
        SourceOccurrenceKey::new(
            SourceRoot::CronieTable(SourceRootId::new(source_id)),
            ordinal,
        ),
        CaptureSequence::new(capture),
    )
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
    let components = [
        ObservationComponent::Discovery,
        ObservationComponent::Configuration,
        ObservationComponent::Runtime,
        ObservationComponent::Schedule,
        ObservationComponent::Command,
        ObservationComponent::Activity,
        ObservationComponent::Runs,
        ObservationComponent::LastResult,
    ];
    let mut rows = components
        .into_iter()
        .map(|component| row(component, Presence::Present))
        .collect::<Vec<_>>();
    rows[1] = row(ObservationComponent::Configuration, Presence::Absent);
    rows[2] = row(ObservationComponent::Runtime, Presence::PresentEmpty);
    let report = diagnose(input(rows));
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

#[test]
fn unknown_presence_keeps_typed_reason_through_report_claim() {
    let report = diagnose(input(vec![row(
        ObservationComponent::Configuration,
        Presence::Unknown(ObservationUnknownReason::UnsupportedSyntax),
    )]));
    assert_eq!(
        report.automations()[0]
            .claims()
            .configuration()
            .conclusion(),
        &Conclusion::Unknown(nix_maintenance_status::UnknownReason::Observation(
            ObservationUnknownReason::UnsupportedSyntax,
        ))
    );
}

#[test]
fn conflicting_observations_become_unknown_with_both_evidence_ids() {
    let absent = ProviderEvidence::with_occurrence(
        Provider::NixOsSystemd,
        Subject::System,
        ObservationComponent::Configuration,
        Presence::Absent,
        occurrence(),
    )
    .unwrap();
    let present = ProviderEvidence::with_occurrence(
        Provider::NixOsSystemd,
        Subject::System,
        ObservationComponent::Configuration,
        Presence::Present,
        occurrence(),
    )
    .unwrap();
    let report = diagnose(input(vec![absent, present]));
    let claim = report.automations()[0].claims().configuration();
    assert!(matches!(
        claim.conclusion(),
        Conclusion::Unknown(nix_maintenance_status::UnknownReason::EvidenceUnavailable(
            UnavailableReason::MalformedEvidence
        ))
    ));
    assert_eq!(claim.provenance().evidence_ids().len(), 2);
}

#[test]
fn identity_free_rows_stay_evidence_and_do_not_create_candidates() {
    let report = diagnose(
        DiagnosticInput::new(
            TargetPlatform::Linux,
            ScanScope::System,
            ScanWindow::new(UNIX_EPOCH, Duration::from_secs(1)).unwrap(),
            ProviderEvidenceSet::new(vec![
                ProviderEvidence::new(
                    Provider::NixOsSystemd,
                    Subject::System,
                    ObservationComponent::Configuration,
                    Presence::Present,
                )
                .unwrap(),
            ])
            .unwrap(),
        )
        .unwrap(),
    );
    assert!(report.automations().is_empty());
    assert_eq!(report.evidence().len(), 1);
}

#[test]
fn proven_logical_aliases_merge_and_union_component_evidence() {
    let configuration = ProviderEvidence::with_occurrence(
        Provider::NixOsSystemd,
        Subject::System,
        ObservationComponent::Configuration,
        Presence::Present,
        systemd_occurrence(1, 1, 0),
    )
    .unwrap();
    let runtime = ProviderEvidence::with_occurrence(
        Provider::NixOsSystemd,
        Subject::System,
        ObservationComponent::Runtime,
        Presence::Present,
        systemd_occurrence(2, 1, 7),
    )
    .unwrap();
    let configuration_alias = ProviderEvidence::with_occurrence(
        Provider::NixOsSystemd,
        Subject::System,
        ObservationComponent::Configuration,
        Presence::Present,
        systemd_occurrence(2, 1, 7),
    )
    .unwrap();
    let report = diagnose(input(vec![runtime, configuration_alias, configuration]));
    assert_eq!(report.automations().len(), 1);
    assert_eq!(
        report.automations()[0]
            .claims()
            .configuration()
            .provenance()
            .evidence_ids()
            .len(),
        2
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
}

#[test]
fn anonymous_source_occurrences_keep_multiplicity_and_present_selection() {
    let first = ProviderEvidence::with_occurrence(
        Provider::Cronie,
        Subject::System,
        ObservationComponent::Configuration,
        Presence::Present,
        anonymous_occurrence(3, 1, 0),
    )
    .unwrap();
    let second = ProviderEvidence::with_occurrence(
        Provider::Cronie,
        Subject::System,
        ObservationComponent::Configuration,
        Presence::Present,
        anonymous_occurrence(3, 2, 0),
    )
    .unwrap();
    let absent = ProviderEvidence::with_occurrence(
        Provider::Cronie,
        Subject::System,
        ObservationComponent::Runtime,
        Presence::Absent,
        anonymous_occurrence(3, 3, 0),
    )
    .unwrap();
    let report = diagnose(input(vec![absent, second, first]));
    assert_eq!(report.automations().len(), 2);
    assert!(
        report
            .automations()
            .iter()
            .all(|automation| automation.provider() == Provider::Cronie)
    );
}

#[test]
fn inventory_order_is_subject_then_provider_catalog_order() {
    let user_cronie = ProviderEvidence::with_occurrence(
        Provider::Cronie,
        Subject::Uid(1000),
        ObservationComponent::Configuration,
        Presence::Present,
        anonymous_occurrence(4, 1, 0),
    )
    .unwrap();
    let system_systemd = row(ObservationComponent::Configuration, Presence::Present);
    let report = diagnose(
        DiagnosticInput::new(
            TargetPlatform::Linux,
            ScanScope::Default,
            ScanWindow::new(UNIX_EPOCH, Duration::from_secs(1)).unwrap(),
            ProviderEvidenceSet::new(vec![user_cronie, system_systemd]).unwrap(),
        )
        .unwrap(),
    );
    assert_eq!(report.automations()[0].subject(), Subject::System);
    assert_eq!(report.automations()[1].subject(), Subject::Uid(1000));
}
