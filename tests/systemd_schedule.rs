use std::time::{Duration, UNIX_EPOCH};

use nix_maintenance_status::{
    CaptureSequence, Conclusion, DefinitionOccurrence, DiagnosticInput, InputError,
    ObservationComponent, Presence, Provider, ProviderEvidence, ProviderEvidenceSet,
    ProviderLogicalKey, ScanScope, ScanWindow, Schedule, SourceOccurrenceKey, SourceRoot,
    SourceRootId, Subject, SystemdManagerIdentity, SystemdSchedule, SystemdTimerPolicy,
    SystemdTrigger, SystemdUnitId, TargetPlatform,
};

fn occurrence() -> DefinitionOccurrence {
    DefinitionOccurrence::new(
        ProviderLogicalKey::Systemd {
            manager: SystemdManagerIdentity::System,
            subject: Subject::System,
            canonical_timer_id: SystemdUnitId::new("nix-gc.timer").unwrap(),
        },
        SourceOccurrenceKey::new(SourceRoot::SystemdUnit(SourceRootId::new(1)), 1),
        CaptureSequence::new(0),
    )
}

#[test]
fn systemd_schedule_preserves_calendar_and_monotonic_triggers() {
    let policy = SystemdTimerPolicy::new(
        Some(Duration::from_secs(60)),
        Some(Duration::from_secs(30)),
        true,
        None,
        false,
        true,
        true,
    );
    let schedule = Schedule::Systemd(
        SystemdSchedule::new(
            vec![
                SystemdTrigger::OnCalendar("03:00:00".to_owned()),
                SystemdTrigger::OnBootSec(Duration::from_millis(300_500)),
            ],
            policy,
        )
        .unwrap(),
    );
    let row = ProviderEvidence::with_occurrence(
        Provider::NixOsSystemd,
        Subject::System,
        ObservationComponent::Schedule,
        Presence::Present,
        occurrence(),
    )
    .unwrap()
    .with_schedule(schedule)
    .unwrap();
    let input = DiagnosticInput::new(
        TargetPlatform::Linux,
        ScanScope::System,
        ScanWindow::new(UNIX_EPOCH, Duration::from_secs(1)).unwrap(),
        ProviderEvidenceSet::new(vec![row]).unwrap(),
    )
    .unwrap();
    let report = nix_maintenance_status::diagnose(input);
    assert!(matches!(
        report.automations()[0].claims().schedule().conclusion(),
        Conclusion::Known(Schedule::Systemd(_))
    ));
}

#[test]
fn systemd_schedule_rejects_empty_or_controlled_calendar() {
    let policy = SystemdTimerPolicy::new(None, None, false, None, false, false, false);
    assert!(SystemdSchedule::new(Vec::new(), policy).is_err());
    assert!(
        SystemdSchedule::new(
            vec![SystemdTrigger::OnCalendar("bad\nvalue".to_owned())],
            policy,
        )
        .is_err()
    );
}

#[test]
fn schedule_attachment_is_single_use_and_present_only() {
    let policy = SystemdTimerPolicy::new(None, None, false, None, false, false, false);
    let schedule = Schedule::Systemd(
        SystemdSchedule::new(
            vec![SystemdTrigger::OnBootSec(Duration::from_secs(1))],
            policy,
        )
        .unwrap(),
    );
    let row = ProviderEvidence::with_occurrence(
        Provider::NixOsSystemd,
        Subject::System,
        ObservationComponent::Schedule,
        Presence::Present,
        occurrence(),
    )
    .unwrap()
    .with_schedule(schedule.clone())
    .unwrap();
    assert_eq!(
        row.with_schedule(schedule),
        Err(InputError::DuplicateEvidenceKey)
    );
    assert!(
        ProviderEvidence::new(
            Provider::NixOsSystemd,
            Subject::System,
            ObservationComponent::Schedule,
            Presence::Absent,
        )
        .unwrap()
        .with_schedule(Schedule::Systemd(
            SystemdSchedule::new(
                vec![SystemdTrigger::OnBootSec(Duration::from_secs(1))],
                policy
            )
            .unwrap(),
        ))
        .is_err()
    );
}
