use std::process::Command;

#[test]
fn help_describes_the_read_only_diagnostic() {
    let output = Command::new(env!("CARGO_BIN_EXE_nix-maintenance-status"))
        .arg("--help")
        .output()
        .expect("run the CLI");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 help output");
    assert!(stdout.contains("Usage: nix-maintenance-status"));
    assert!(stdout.contains("read-only"));
}

#[cfg(target_os = "macos")]
#[test]
fn default_command_reports_the_effective_macos_status() {
    let output = Command::new(env!("CARGO_BIN_EXE_nix-maintenance-status"))
        .output()
        .expect("run the CLI");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 status output");
    let lines = stdout
        .lines()
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();

    assert_eq!(lines[0], "Nix maintenance status");
    assert!(lines[1].starts_with("Configuration: "));
    assert!(lines[2].starts_with("Runtime: "));
    assert!(lines[3].starts_with("Consistency: "));
    assert!(lines[1..].iter().all(|line| {
        line.ends_with("[observed]") || line.ends_with("[inferred]") || line.ends_with("[unknown]")
    }));
    assert!(!stdout.contains("Garbage collection:"));
}

#[cfg(not(target_os = "macos"))]
#[test]
fn default_command_rejects_unsupported_platforms() {
    let output = Command::new(env!("CARGO_BIN_EXE_nix-maintenance-status"))
        .output()
        .expect("run the CLI");

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 error output");
    assert!(stderr.contains("currently supports macOS with nix-darwin"));
}

#[test]
fn version_reports_the_package_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_nix-maintenance-status"))
        .arg("--version")
        .output()
        .expect("run the CLI");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("UTF-8 version output"),
        format!("nix-maintenance-status {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn unknown_options_fail_with_a_useful_message() {
    let output = Command::new(env!("CARGO_BIN_EXE_nix-maintenance-status"))
        .arg("--unknown")
        .output()
        .expect("run the CLI");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 error output");
    assert!(stderr.contains("unknown option: --unknown"));
    assert!(stderr.contains("--help"));
}
