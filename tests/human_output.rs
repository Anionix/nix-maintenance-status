use nix_maintenance_status::{LastResult, MaintenanceStatus, render_human, report_from_launchd};

const MINIMAL_LOADED_JOB: &str = r#"
system/org.nixos.nix-gc = {
    state = not running
    runs = 2
    last exit code = 0
}
"#;

#[test]
fn explains_the_configuration_and_runtime_layers() {
    let status = MaintenanceStatus {
        job: "org.nixos.nix-gc".to_owned(),
        configured: true,
        loaded: true,
        running: false,
        runs: Some(0),
        last_result: LastResult::NeverRun,
        command: Some("/nix/store/example-nix/bin/nix-collect-garbage".to_owned()),
        schedule: Some("weekday 7 at 03:15".to_owned()),
    };

    let output = render_human(&status);

    assert!(output.contains("Garbage collection: enabled"));
    assert!(output.contains("Configuration: nix-darwin nix.gc.automatic (inferred)"));
    assert!(output.contains("Runtime job: org.nixos.nix-gc (loaded, idle)"));
    assert!(output.contains("Schedule: weekday 7 at 03:15"));
    assert!(output.contains("Last result: never run since the job was loaded"));
    assert!(output.contains("Nix GC itself is provided by Nix"));
}

#[test]
fn builds_a_report_from_a_launchd_probe() {
    let output = report_from_launchd(Some(MINIMAL_LOADED_JOB), true)
        .expect("valid launchd output should produce a report");

    assert!(output.contains("Garbage collection: enabled"));
    assert!(output.contains("Runs since load: 2"));
    assert!(output.contains("Last result: success"));
}

#[test]
fn absent_legacy_evidence_does_not_infer_nix_darwin_configuration() {
    let output = report_from_launchd(None, false).expect("absence is a valid report");

    assert!(output.contains("Configuration: not detected (observed)"));
    assert!(!output.contains("Configuration: nix-darwin nix.gc.automatic"));
}
