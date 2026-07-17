//! Test-only Linux transport probe used by the isolated NixOS VM fixtures.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("systemd VM probe is Linux-only");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    use nix_maintenance_status::{
        CaptureSequence, ObservationComponent, Presence, SourceRootId, SystemdBusScope,
        SystemdBusTransport, normalize_systemd_snapshot,
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
    // seam. It emits normalized enum labels, never raw bus data, and exits 2
    // on transport/normalization failure without retry, mutation, or GC.
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
            Presence::Absent => "absent",
            Presence::Unavailable(_) => "unknown",
        })
        .unwrap_or("not-applicable");
    println!(
        "scope={} command={} observations={}",
        if current_user {
            "current-user"
        } else {
            "system"
        },
        command,
        report.evidence().entries().len()
    );
}
