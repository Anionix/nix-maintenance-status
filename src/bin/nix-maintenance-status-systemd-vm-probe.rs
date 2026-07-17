//! Test-only Linux transport probe used by the isolated NixOS VM fixtures.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("systemd VM probe is Linux-only");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    use nix_maintenance_status::{
        AuthorityResolution, AuthorityRole, CaptureSequence, Conclusion, ConsistencyValue,
        DiagnosticInput, ObservationComponent, Presence, ScanScope, ScanWindow, SourceRootId,
        SystemdBusScope, SystemdBusTransport, TargetPlatform, diagnose, normalize_systemd_snapshot,
    };

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
    let transport = SystemdBusTransport::connect(scope).unwrap_or_else(|_| {
        eprintln!("fixed local systemd bus unavailable");
        std::process::exit(2);
    });
    let snapshot = transport
        .probe_nix_gc(SourceRootId::new(1), CaptureSequence::new(1))
        .unwrap_or_else(|_| {
            eprintln!("typed systemd probe unavailable");
            std::process::exit(2);
        });
    let report = normalize_systemd_snapshot(snapshot, "0000000000000000000000000000000000000000")
        .unwrap_or_else(|_| {
            eprintln!("typed systemd normalization unavailable");
            std::process::exit(2);
        });
    let command = report
        .evidence()
        .entries()
        .iter()
        .find(|entry| entry.component() == ObservationComponent::Command)
        .map(|entry| match entry.presence() {
            Presence::Present => "present",
            Presence::PresentEmpty => "present",
            Presence::Absent => "absent",
            Presence::Unavailable(_) => "unknown",
        })
        .unwrap_or("not-applicable");
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
        "scope={} automations={} authority={} consistency={} schedule={} command={} observations={}",
        if current_user {
            "current-user"
        } else {
            "system"
        },
        gc_report.automations().len(),
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
