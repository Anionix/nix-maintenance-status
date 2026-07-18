use std::time::Duration;

use nix_maintenance_status::{
    AuthorityResolution, AuthorityUnknownReason, CaptureSequence, ObservationComponent, Presence,
    SourceRootId, Subject, SystemdBusError, SystemdBusSnapshot, SystemdManagerIdentity,
    SystemdTimerPolicy, SystemdTimerProperties, SystemdTrigger, UnavailableReason,
    duration_from_usec, normalize_nix_gc_state, normalize_systemd_snapshot,
};

fn properties(target: &str) -> SystemdTimerProperties {
    SystemdTimerProperties::new(
        nix_maintenance_status::SystemdUnitId::new(target).unwrap(),
        vec![
            SystemdTrigger::OnCalendar("03:15:00".to_owned()),
            SystemdTrigger::OnBootSec(Duration::from_millis(500)),
        ],
        SystemdTimerPolicy::new(
            Some(Duration::from_micros(100_000)),
            Some(Duration::from_millis(250)),
            true,
            Some(Duration::from_millis(50)),
            true,
            true,
            false,
        ),
    )
    .unwrap()
}

fn snapshot(
    manager: SystemdManagerIdentity,
    unit: &str,
    loaded: Presence,
    generation_after: u64,
    properties: Result<Option<SystemdTimerProperties>, SystemdBusError>,
) -> SystemdBusSnapshot {
    snapshot_with_config(
        manager,
        unit,
        Presence::Present,
        loaded,
        generation_after,
        properties,
    )
}

fn snapshot_with_config(
    manager: SystemdManagerIdentity,
    unit: &str,
    configured: Presence,
    loaded: Presence,
    generation_after: u64,
    properties: Result<Option<SystemdTimerProperties>, SystemdBusError>,
) -> SystemdBusSnapshot {
    SystemdBusSnapshot::new(
        manager,
        if manager == SystemdManagerIdentity::System {
            Subject::System
        } else {
            Subject::uid(1000)
        },
        nix_maintenance_status::SystemdUnitId::new(unit).unwrap(),
        SourceRootId::new(7),
        CaptureSequence::new(1),
        configured,
        loaded,
        3,
        generation_after,
        properties,
    )
    .unwrap()
}

const REVISION: &str = "e8d924d50a462f89166e31a27bdcbbade35fd8e6";

#[test]
fn exact_gc_timer_observation_preserves_schedule_without_authority_injection() {
    let report = normalize_systemd_snapshot(
        snapshot(
            SystemdManagerIdentity::System,
            "nix-gc.timer",
            Presence::Present,
            3,
            Ok(Some(properties("nix-gc.service"))),
        ),
        REVISION,
    )
    .unwrap();
    assert!(matches!(
        report.authority(),
        AuthorityResolution::Resolved(_)
    ));
    assert_eq!(report.evidence().entries().len(), 4);
    assert!(
        report
            .evidence()
            .entries()
            .iter()
            .all(|entry| entry.occurrence().is_some())
    );
}

#[test]
fn configuration_and_runtime_remain_independent() {
    for (configured, loaded) in [
        (Presence::Present, Presence::Present),
        (Presence::Present, Presence::Absent),
        (Presence::Absent, Presence::Present),
        (Presence::Absent, Presence::Absent),
    ] {
        let report = normalize_systemd_snapshot(
            snapshot_with_config(
                SystemdManagerIdentity::System,
                "nix-gc.timer",
                configured,
                loaded,
                3,
                Ok(Some(properties("nix-gc.service"))),
            ),
            REVISION,
        )
        .unwrap();
        assert_eq!(
            report
                .evidence()
                .entries()
                .iter()
                .find(|entry| entry.component() == ObservationComponent::Configuration)
                .unwrap()
                .presence(),
            configured
        );
        assert_eq!(
            report
                .evidence()
                .entries()
                .iter()
                .find(|entry| entry.component() == ObservationComponent::Runtime)
                .unwrap()
                .presence(),
            loaded
        );
        if configured == Presence::Present && loaded == Presence::Absent {
            assert!(
                report
                    .evidence()
                    .entries()
                    .iter()
                    .any(|entry| entry.component() == ObservationComponent::Schedule
                        && entry.presence() == Presence::Present)
            );
        }
    }

    let failed_properties = normalize_systemd_snapshot(
        snapshot(
            SystemdManagerIdentity::System,
            "nix-gc.timer",
            Presence::Absent,
            3,
            Err(SystemdBusError::AccessDenied),
        ),
        REVISION,
    )
    .unwrap();
    assert_eq!(
        failed_properties
            .evidence()
            .entries()
            .iter()
            .find(|entry| entry.component() == ObservationComponent::Schedule)
            .unwrap()
            .presence(),
        Presence::Unavailable(UnavailableReason::PermissionDenied)
    );
}

#[test]
fn command_unknown_does_not_erase_schedule() {
    let report = normalize_systemd_snapshot(
        snapshot(
            SystemdManagerIdentity::System,
            "nix-gc.timer",
            Presence::Present,
            3,
            Ok(Some(properties("nix-gc.service"))),
        ),
        REVISION,
    )
    .unwrap();
    assert!(report.evidence().entries().iter().any(|entry| {
        entry.component() == ObservationComponent::Schedule && entry.presence() == Presence::Present
    }));
}

#[test]
fn no_job_is_absent_but_bus_failures_are_unavailable() {
    assert_eq!(
        normalize_nix_gc_state(Err(SystemdBusError::NoSuchUnit)),
        Presence::Absent
    );
    assert_eq!(normalize_nix_gc_state(Ok(false)), Presence::Absent);
    for error in [
        SystemdBusError::AccessDenied,
        SystemdBusError::NoReply,
        SystemdBusError::InvalidSignature,
        SystemdBusError::UnknownMethod,
        SystemdBusError::ResourceLimitExceeded,
        SystemdBusError::ServiceUnknown,
        SystemdBusError::NameHasNoOwner,
        SystemdBusError::Disconnected,
        SystemdBusError::OperationFailed,
    ] {
        assert!(matches!(
            normalize_nix_gc_state(Err(error)),
            Presence::Unavailable(_)
        ));
    }
}

fn assert_identity_free(report: &nix_maintenance_status::SystemdNormalizedObservation) {
    assert!(
        report
            .evidence()
            .entries()
            .iter()
            .all(|entry| entry.occurrence().is_none())
    );
}

#[test]
fn unknown_revision_foreign_timer_and_user_manager_keep_identity_free_evidence() {
    let unknown_revision = normalize_systemd_snapshot(
        snapshot(
            SystemdManagerIdentity::System,
            "nix-gc.timer",
            Presence::Present,
            3,
            Ok(Some(properties("nix-gc.service"))),
        ),
        "0000000000000000000000000000000000000000",
    )
    .unwrap();
    assert_eq!(
        unknown_revision.authority(),
        AuthorityResolution::Unresolved(AuthorityUnknownReason::IdentityNotCatalogued)
    );
    assert!(
        unknown_revision
            .evidence()
            .entries()
            .iter()
            .all(|entry| entry.occurrence().is_some())
    );

    let foreign_timer = normalize_systemd_snapshot(
        snapshot(
            SystemdManagerIdentity::System,
            "other.timer",
            Presence::Present,
            3,
            Ok(Some(properties("nix-gc.service"))),
        ),
        REVISION,
    )
    .unwrap();
    assert_eq!(
        foreign_timer.authority(),
        AuthorityResolution::Unresolved(AuthorityUnknownReason::ExactBasisUnverifiable)
    );
    assert_identity_free(&foreign_timer);

    let wrong_target = normalize_systemd_snapshot(
        snapshot(
            SystemdManagerIdentity::System,
            "nix-gc.timer",
            Presence::Present,
            3,
            Ok(Some(properties("unrelated.service"))),
        ),
        REVISION,
    )
    .unwrap();
    assert_eq!(
        wrong_target.authority(),
        AuthorityResolution::Unresolved(AuthorityUnknownReason::ExactBasisUnverifiable)
    );
    assert_identity_free(&wrong_target);

    let user_manager = normalize_systemd_snapshot(
        snapshot(
            SystemdManagerIdentity::User,
            "nix-gc.timer",
            Presence::Present,
            3,
            Ok(Some(properties("nix-gc.service"))),
        ),
        REVISION,
    )
    .unwrap();
    assert_eq!(user_manager.authority(), AuthorityResolution::NotApplicable);
    assert_identity_free(&user_manager);
}

#[test]
fn changed_manager_and_getall_failures_are_local_schedule_unknowns() {
    // systemd v261 has no documented read-generation property in the live VM;
    // this typed fixture is the canonical changed-during-read proof. It must
    // remain Unknown and never be presented as an atomic guest observation.
    let changed = normalize_systemd_snapshot(
        snapshot(
            SystemdManagerIdentity::System,
            "nix-gc.timer",
            Presence::Present,
            4,
            Ok(Some(properties("nix-gc.service"))),
        ),
        REVISION,
    )
    .unwrap();
    assert!(matches!(
        changed.authority(),
        AuthorityResolution::Resolved(_)
    ));
    assert!(
        changed
            .evidence()
            .entries()
            .iter()
            .all(|entry| entry.occurrence().is_some())
    );
    assert!(matches!(
        changed
            .evidence()
            .entries()
            .iter()
            .find(|entry| entry.component() == ObservationComponent::Schedule)
            .expect("changed reads retain a schedule row")
            .presence(),
        Presence::Unavailable(UnavailableReason::ChangedDuringRead)
    ));

    for (properties, expected) in [
        (Ok(None), UnavailableReason::MalformedEvidence),
        (
            Err(SystemdBusError::AccessDenied),
            UnavailableReason::PermissionDenied,
        ),
        (
            Err(SystemdBusError::InvalidSignature),
            UnavailableReason::MalformedEvidence,
        ),
    ] {
        let report = normalize_systemd_snapshot(
            snapshot_with_config(
                SystemdManagerIdentity::System,
                "nix-gc.timer",
                Presence::Present,
                Presence::Present,
                3,
                properties,
            ),
            REVISION,
        )
        .unwrap();
        assert_identity_free(&report);
        let schedule = report
            .evidence()
            .entries()
            .iter()
            .find(|entry| entry.component() == ObservationComponent::Schedule)
            .unwrap();
        assert_eq!(schedule.presence(), Presence::Unavailable(expected));
        assert!(schedule.occurrence().is_none());
        assert!(matches!(
            report.authority(),
            AuthorityResolution::Unresolved(_)
        ));
    }
}

#[test]
fn fractional_microseconds_are_lossless() {
    assert_eq!(duration_from_usec(500_000), Duration::from_millis(500));
    assert_eq!(duration_from_usec(u64::MAX).as_micros(), u64::MAX as u128);
    assert_eq!(
        SystemdBusError::AccessDenied.presence(),
        Presence::Unavailable(UnavailableReason::PermissionDenied)
    );
}
