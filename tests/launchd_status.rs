use nix_maintenance_status::{LastResult, diagnose_launchd, parse_launchd_status};

const LOADED_GC_JOB: &str = r#"
system/org.nixos.nix-gc = {
	active count = 0
	path = /Library/LaunchDaemons/org.nixos.nix-gc.plist
	type = LaunchDaemon
	state = not running

	program = /bin/sh
	arguments = {
		/bin/sh
		-c
		/bin/wait4path /nix/store && exec /nix/store/example-nix/bin/nix-collect-garbage --delete-older-than 30d
	}

	runs = 0
	last exit code = (never exited)

	event triggers = {
		org.nixos.nix-gc.123 => {
			descriptor = {
				"Minute" => 15
				"Hour" => 3
				"Weekday" => 7
			}
		}
	}
}
"#;

#[test]
fn parses_effective_launchd_gc_status() {
    let status = parse_launchd_status(LOADED_GC_JOB).expect("valid launchd output");

    assert_eq!(status.job, "org.nixos.nix-gc");
    assert!(status.configured);
    assert!(status.loaded);
    assert!(!status.running);
    assert_eq!(status.runs, Some(0));
    assert_eq!(status.last_result, LastResult::NeverRun);
    assert_eq!(
        status.command.as_deref(),
        Some("/nix/store/example-nix/bin/nix-collect-garbage --delete-older-than 30d")
    );
    assert_eq!(status.schedule.as_deref(), Some("weekday 7 at 03:15"));
}

#[test]
fn reports_when_automatic_gc_is_not_detected() {
    let status = diagnose_launchd(None, false).expect("an absent job is a valid status");

    assert!(!status.configured);
    assert!(!status.loaded);
    assert_eq!(status.last_result, LastResult::Unknown);
}
