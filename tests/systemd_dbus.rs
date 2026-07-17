use std::time::Duration;

use nix_maintenance_status::{
    AuthorityResolution, CaptureSequence, Presence, SourceRootId, Subject, SystemdAdapterError,
    SystemdBusError, SystemdBusSnapshot, SystemdManagerIdentity, SystemdTimerPolicy,
    SystemdTimerProperties, SystemdTrigger, duration_from_usec, normalize_bus_state,
    normalize_systemd_snapshot, resolve_nix_gc_authority,
};

fn properties() -> SystemdTimerProperties {
    SystemdTimerProperties::new(
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

fn snapshot(configured: Presence, loaded: Presence) -> SystemdBusSnapshot {
    SystemdBusSnapshot::new(
        SystemdManagerIdentity::System,
        Subject::System,
        SourceRootId::new(7),
        CaptureSequence::new(1),
        configured,
        loaded,
        3,
        3,
        Some(properties()),
    )
    .unwrap()
}

#[test]
fn read_only_snapshot_normalizes_exact_nix_gc_unit() {
    let authority = resolve_nix_gc_authority("e8d924d50a462f89166e31a27bdcbbade35fd8e6");
    assert!(matches!(authority, AuthorityResolution::Resolved(_)));
    let normalized =
        normalize_systemd_snapshot(snapshot(Presence::Present, Presence::Present), authority)
            .unwrap();
    assert_eq!(normalized.evidence().entries().len(), 3);
    assert!(matches!(
        normalized.authority(),
        AuthorityResolution::Resolved(_)
    ));
}

#[test]
fn finite_no_job_is_absent_but_bus_failures_are_unavailable() {
    assert_eq!(
        normalize_bus_state(Err(SystemdBusError::NoSuchUnit)),
        Presence::Absent
    );
    assert_eq!(
        normalize_bus_state(Err(SystemdBusError::AccessDenied)),
        Presence::Unavailable(nix_maintenance_status::UnavailableReason::PermissionDenied)
    );
    assert_eq!(normalize_bus_state(Ok(false)), Presence::Absent);
}

#[test]
fn changed_manager_invalidates_local_observation_and_unknown_authority_stops_gc_claim() {
    let changed = SystemdBusSnapshot::new(
        SystemdManagerIdentity::System,
        Subject::System,
        SourceRootId::new(7),
        CaptureSequence::new(1),
        Presence::Present,
        Presence::Present,
        3,
        4,
        None,
    )
    .unwrap();
    let authority = resolve_nix_gc_authority("0000000000000000000000000000000000000000");
    assert!(matches!(
        normalize_systemd_snapshot(changed, authority),
        Err(SystemdAdapterError::AuthorityUnknown(_))
    ));
    assert_eq!(
        duration_from_usec(500_000),
        Some(Duration::from_millis(500))
    );
}
