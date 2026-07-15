use nix_maintenance_status::{GcPlist, LaunchdJob, Probe, ProbeFailure};

const EXPECTED_JOB_HEADING: &str = "system/org.nixos.nix-gc = {";
const LAUNCHCTL_SERVICE_NOT_FOUND_EXIT: i32 = 113;

// LLM contract: exit 0 plus the expected heading is Observed; service-not-found is
// Absent. Other exits, spawn failures, malformed bytes, and filesystem errors are
// Unavailable. Probe failures retain no raw output or OS error text.
pub(crate) fn normalize_launchd(code: Option<i32>, stdout: &[u8]) -> Probe<LaunchdJob> {
    match code {
        Some(LAUNCHCTL_SERVICE_NOT_FOUND_EXIT) => Probe::Absent,
        Some(0) => match std::str::from_utf8(stdout) {
            Ok(output)
                if output
                    .lines()
                    .any(|line| line.trim() == EXPECTED_JOB_HEADING) =>
            {
                Probe::Observed(LaunchdJob::new())
            }
            _ => Probe::Unavailable(ProbeFailure::MalformedOutput),
        },
        _ => Probe::Unavailable(ProbeFailure::CommandFailed),
    }
}

pub(crate) fn normalize_launchd_output(
    result: std::io::Result<std::process::Output>,
) -> Probe<LaunchdJob> {
    match result {
        Ok(output) => normalize_launchd(output.status.code(), &output.stdout),
        Err(_) => Probe::Unavailable(ProbeFailure::CommandUnavailable),
    }
}

pub(crate) fn normalize_plist(result: std::io::Result<bool>) -> Probe<GcPlist> {
    match result {
        Ok(true) => Probe::Observed(GcPlist::new()),
        Ok(false) => Probe::Absent,
        Err(_) => Probe::Unavailable(ProbeFailure::FileSystemUnavailable),
    }
}

pub(crate) fn launchd_probe() -> Probe<LaunchdJob> {
    normalize_launchd_output(
        std::process::Command::new("/bin/launchctl")
            .args(["print", "system/org.nixos.nix-gc"])
            .output(),
    )
}

pub(crate) fn plist_probe() -> Probe<GcPlist> {
    normalize_plist(
        std::path::Path::new("/Library/LaunchDaemons/org.nixos.nix-gc.plist").try_exists(),
    )
}

#[cfg(test)]
mod tests {
    use nix_maintenance_status::{GcPlist, LaunchdJob, Probe, ProbeFailure};

    use super::{normalize_launchd, normalize_launchd_output, normalize_plist};

    #[test]
    fn normalizes_launchd_outcomes_without_retaining_raw_output() {
        #[rustfmt::skip]
        let cases: &[(Option<i32>, &[u8], Probe<LaunchdJob>)] = &[
            (Some(0),   b"system/org.nixos.nix-gc = {\n}\n", Probe::Observed(LaunchdJob::new())),
            (Some(113), b"not found", Probe::Absent),
            (Some(1),   b"private", Probe::Unavailable(ProbeFailure::CommandFailed)),
            (Some(0),   b"unexpected", Probe::Unavailable(ProbeFailure::MalformedOutput)),
            (Some(0),   &[0xff], Probe::Unavailable(ProbeFailure::MalformedOutput)),
        ];
        for (code, output, expected) in cases {
            assert_eq!(normalize_launchd(*code, output), *expected);
        }
        let failure = std::io::Error::new(std::io::ErrorKind::NotFound, "private");
        assert_eq!(
            normalize_launchd_output(Err(failure)),
            Probe::Unavailable(ProbeFailure::CommandUnavailable)
        );
    }

    #[test]
    fn normalizes_plist_presence_and_io_failure() {
        assert_eq!(normalize_plist(Ok(true)), Probe::Observed(GcPlist::new()));
        assert_eq!(normalize_plist(Ok(false)), Probe::Absent);
        let failure = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "private");
        assert_eq!(
            normalize_plist(Err(failure)),
            Probe::Unavailable(ProbeFailure::FileSystemUnavailable)
        );
    }
}
