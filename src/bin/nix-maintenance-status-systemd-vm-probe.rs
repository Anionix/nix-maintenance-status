//! Test-only Linux transport probe used by the isolated NixOS VM fixtures.

#[cfg(target_os = "linux")]
use nix_maintenance_status::{
    AuthorityResolution, AuthorityRole, AuthorityUnknownReason, CaptureSequence, Conclusion,
    ConsistencyValue, DiagnosticInput, ObservationComponent, Presence, Provider, ProviderEvidence,
    ProviderEvidenceSet, ScanScope, ScanWindow, SourceRootId, Subject, SystemdBusScope,
    SystemdBusTransport, SystemdTransportError, TargetPlatform, UnavailableReason, diagnose,
    normalize_systemd_snapshot,
};

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("systemd VM probe is Linux-only");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    let current_user = std::env::args().any(|arg| arg == "--current-user");
    let scope = if current_user {
        let uid = std::env::var("UID")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(1000);
        SystemdBusScope::current_user(uid).unwrap_or_else(|_| {
            eprintln!("current-user scope validation failed");
            std::process::exit(2);
        })
    } else {
        SystemdBusScope::System
    };

    // LLM contract: this helper only exercises the fixed local D-Bus read
    // seam, then renders the typed inventory. It emits normalized enum labels,
    // never raw bus data, and exits 2 on transport/classification failure
    // without retry, mutation, telemetry, or GC.
    let transport = SystemdBusTransport::connect(scope)
        .unwrap_or_else(|error| render_unavailable(scope, transport_error_reason(error)));
    let snapshot = transport
        .probe_nix_gc(SourceRootId::new(1), CaptureSequence::new(1))
        .unwrap_or_else(|error| render_unavailable(scope, transport_error_reason(error)));
    let report = normalize_systemd_snapshot(snapshot, "0000000000000000000000000000000000000000")
        .unwrap_or_else(|_| render_unavailable(scope, UnavailableReason::MalformedEvidence));
    let command = report
        .evidence()
        .entries()
        .iter()
        .find(|entry| entry.component() == ObservationComponent::Command)
        .map(|entry| match entry.presence() {
            Presence::Present => "present",
            Presence::PresentEmpty => "present",
            Presence::Absent => "absent",
            Presence::Unknown(_) | Presence::Unavailable(_) => "unknown",
            _ => "unknown",
        })
        .unwrap_or("not-applicable");
    let configuration = evidence_presence(report.evidence(), ObservationComponent::Configuration);
    let runtime = evidence_presence(report.evidence(), ObservationComponent::Runtime);
    let input = DiagnosticInput::new(
        TargetPlatform::Linux,
        if current_user {
            ScanScope::CurrentUser
        } else {
            ScanScope::System
        },
        ScanWindow::new(std::time::UNIX_EPOCH, std::time::Duration::from_secs(1)).unwrap_or_else(
            |_| {
                eprintln!("fixed scan window validation failed");
                std::process::exit(2);
            },
        ),
        report.evidence().clone(),
    )
    .unwrap_or_else(|_| {
        eprintln!("typed systemd evidence validation failed");
        std::process::exit(2);
    });
    let gc_report = diagnose(input);
    let automation = gc_report.automations().first();
    let authority = automation
        .map(|automation| {
            automation
                .claims()
                .configuration()
                .provenance()
                .authority(AuthorityRole::AutomationMapping)
        })
        .unwrap_or_else(|| report.authority());
    let authority = authority_label(authority);
    let consistency = automation
        .map(
            |automation| match automation.claims().consistency().conclusion() {
                Conclusion::Known(ConsistencyValue::Consistent) => "consistent",
                Conclusion::Known(ConsistencyValue::Inconsistent) => "inconsistent",
                Conclusion::Known(_) | Conclusion::Unknown(_) => "unknown",
            },
        )
        .unwrap_or("not-applicable");
    let schedule = automation
        .map(
            |automation| match automation.claims().schedule().conclusion() {
                Conclusion::Known(_) => "known",
                Conclusion::Unknown(_) => "unknown",
            },
        )
        .unwrap_or("unknown");
    println!(
        "scope={} automations={} configuration={} runtime={} authority={} consistency={} schedule={} command={} observations={}",
        if current_user {
            "current-user"
        } else {
            "system"
        },
        gc_report.automations().len(),
        configuration,
        runtime,
        authority,
        consistency,
        schedule,
        command,
        report.evidence().entries().len()
    );
}

#[cfg(target_os = "linux")]
fn authority_label(authority: nix_maintenance_status::AuthorityResolution) -> &'static str {
    // LLM contract: Authority is a four-state value; only catalog resolution
    // is "resolved", and no unknown/not-applicable state is upgraded by output.
    match authority {
        nix_maintenance_status::AuthorityResolution::Resolved(_) => "resolved",
        nix_maintenance_status::AuthorityResolution::Unresolved(_) => "unknown",
        nix_maintenance_status::AuthorityResolution::NotClaimed => "not-claimed",
        nix_maintenance_status::AuthorityResolution::NotApplicable => "not-applicable",
    }
}

#[cfg(target_os = "linux")]
fn evidence_presence(
    evidence: &nix_maintenance_status::ProviderEvidenceSet,
    component: nix_maintenance_status::ObservationComponent,
) -> &'static str {
    evidence
        .entries()
        .iter()
        .find(|entry| entry.component() == component)
        .map_or("unknown", |entry| match entry.presence() {
            Presence::Present | Presence::PresentEmpty => "present",
            Presence::Absent => "absent",
            Presence::Unknown(_) | Presence::Unavailable(_) => "unknown",
            _ => "unknown",
        })
}

#[cfg(target_os = "linux")]
fn transport_error_reason(error: SystemdTransportError) -> UnavailableReason {
    // LLM contract: failures map to typed UnavailableReason, never raw text or Absent.
    match error {
        SystemdTransportError::Bus(error) => match error.presence() {
            Presence::Unknown(reason) | Presence::Unavailable(reason) => reason,
            Presence::Absent | Presence::PresentEmpty | Presence::Present => {
                UnavailableReason::InterfaceUnavailable
            }
            _ => UnavailableReason::InterfaceUnavailable,
        },
        SystemdTransportError::InvalidInput(_) => UnavailableReason::MalformedEvidence,
        _ => UnavailableReason::InterfaceUnavailable,
    }
}

#[cfg(target_os = "linux")]
fn unavailable_evidence(scope: SystemdBusScope, reason: UnavailableReason) -> ProviderEvidenceSet {
    // LLM contract: a failed scope yields only typed Unavailable rows; no Authority or occurrence.
    let subject = scope.subject();
    let mut entries = vec![
        ProviderEvidence::new(
            Provider::NixOsSystemd,
            subject,
            ObservationComponent::Configuration,
            Presence::Unavailable(reason),
        )
        .expect("fixed unavailable configuration row"),
        ProviderEvidence::new(
            Provider::NixOsSystemd,
            subject,
            ObservationComponent::Runtime,
            Presence::Unavailable(reason),
        )
        .expect("fixed unavailable runtime row"),
        ProviderEvidence::new(
            Provider::NixOsSystemd,
            subject,
            ObservationComponent::Schedule,
            Presence::Unavailable(reason),
        )
        .expect("fixed unavailable schedule row"),
    ];
    if scope == SystemdBusScope::System {
        entries.push(
            ProviderEvidence::new(
                Provider::NixOsSystemd,
                Subject::System,
                ObservationComponent::Command,
                Presence::Unavailable(reason),
            )
            .expect("fixed unavailable command row"),
        );
    }
    ProviderEvidenceSet::new(entries).expect("fixed unavailable evidence set")
}

#[cfg(target_os = "linux")]
fn unavailable_label(reason: UnavailableReason) -> &'static str {
    match reason {
        UnavailableReason::PermissionDenied => "permission-denied",
        UnavailableReason::MalformedEvidence => "malformed-evidence",
        UnavailableReason::TimedOut => "timed-out",
        UnavailableReason::InterfaceUnavailable => "interface-unavailable",
        _ => "unavailable",
    }
}

#[cfg(target_os = "linux")]
fn render_unavailable(scope: SystemdBusScope, reason: UnavailableReason) -> ! {
    // LLM contract: failed local transport stays Unavailable; emit a normalized reason and exit 2.
    let evidence = unavailable_evidence(scope, reason);
    let input = DiagnosticInput::new(
        TargetPlatform::Linux,
        match scope {
            SystemdBusScope::System => ScanScope::System,
            SystemdBusScope::CurrentUser(_) => ScanScope::CurrentUser,
        },
        ScanWindow::new(std::time::UNIX_EPOCH, std::time::Duration::from_secs(1))
            .expect("fixed scan window"),
        evidence.clone(),
    )
    .expect("fixed unavailable evidence validates");
    let report = diagnose(input);
    let (scope_label, authority, command) = match scope {
        SystemdBusScope::System => (
            "system",
            authority_label(AuthorityResolution::Unresolved(
                AuthorityUnknownReason::IdentityUnavailable,
            )),
            "unknown",
        ),
        SystemdBusScope::CurrentUser(_) => ("current-user", "not-applicable", "not-applicable"),
    };
    println!(
        "scope={scope_label} automations={} configuration=unknown runtime=unknown authority={authority} consistency=not-applicable schedule=unknown command={command} observations={} unavailable={}",
        report.automations().len(),
        evidence.entries().len(),
        unavailable_label(reason),
    );
    std::process::exit(2);
}
