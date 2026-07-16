use nix_maintenance_status::{
    InputError, ObservationComponent, Presence, Provider, ProviderEvidence, ProviderEvidenceSet,
    Subject,
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
    assert_eq!(
        ProviderEvidenceSet::new(Vec::new()),
        Err(InputError::EmptyEvidence)
    );
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
    assert_eq!(
        ProviderEvidence::new(
            Provider::NixOsSystemd,
            Subject::unresolved(0),
            ObservationComponent::Discovery,
            Presence::Present,
        ),
        Err(InputError::InvalidSubject)
    );
}
