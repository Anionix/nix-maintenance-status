use nix_maintenance_status::{
    InputError, ObservationComponent, Presence, Provider, ProviderEvidence, ProviderEvidenceSet,
    ScanScope, Subject, TargetPlatform, UnavailableReason, validate_input,
};

fn evidence(subject: Subject, component: ObservationComponent) -> ProviderEvidence {
    ProviderEvidence::new(
        Provider::NixOsSystemd,
        subject,
        component,
        Presence::Present,
    )
    .unwrap()
}

#[test]
fn evidence_set_is_deterministic_and_rejects_duplicate_keys() {
    let values = ProviderEvidenceSet::new(vec![
        evidence(Subject::System, ObservationComponent::Runtime),
        evidence(Subject::System, ObservationComponent::Discovery),
    ])
    .unwrap();
    assert_eq!(
        values.entries()[0].component(),
        ObservationComponent::Discovery
    );
    assert_eq!(
        values.entries()[1].component(),
        ObservationComponent::Runtime
    );
    assert_eq!(
        ProviderEvidenceSet::new(vec![
            evidence(Subject::System, ObservationComponent::Discovery),
            evidence(Subject::System, ObservationComponent::Discovery),
        ]),
        Err(InputError::DuplicateEvidenceKey)
    );
}

#[test]
fn scope_and_platform_validation_is_explicit() {
    let system = ProviderEvidenceSet::new(vec![evidence(
        Subject::System,
        ObservationComponent::Discovery,
    )])
    .unwrap();
    validate_input(TargetPlatform::Linux, ScanScope::System, &system).unwrap();
    assert_eq!(
        validate_input(TargetPlatform::MacOs, ScanScope::System, &system),
        Err(InputError::InvalidPlatformProvider)
    );

    let entry = ProviderEvidence::new(
        Provider::NixOsSystemd,
        Subject::unresolved(1),
        ObservationComponent::Discovery,
        Presence::Unavailable(UnavailableReason::ExternalIdentityMayBeRelevant),
    )
    .unwrap();
    let values = ProviderEvidenceSet::new(vec![
        evidence(Subject::System, ObservationComponent::Discovery),
        evidence(Subject::uid(1000), ObservationComponent::Discovery),
        entry,
    ])
    .unwrap();
    assert_eq!(
        validate_input(TargetPlatform::Linux, ScanScope::Default, &values),
        Err(InputError::InvalidScope)
    );
    validate_input(TargetPlatform::Linux, ScanScope::AllUsers, &values).unwrap();

    let users = ProviderEvidenceSet::new(vec![
        evidence(Subject::uid(1000), ObservationComponent::Discovery),
        evidence(Subject::uid(1001), ObservationComponent::Discovery),
    ])
    .unwrap();
    assert_eq!(
        validate_input(TargetPlatform::Linux, ScanScope::CurrentUser, &users),
        Err(InputError::InvalidScope)
    );
}
