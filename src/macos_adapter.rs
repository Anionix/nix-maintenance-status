use nix_maintenance_status::{
    CaptureSequence, DefinitionOccurrence, DiagnosticInput, InputError, LaunchdDomain,
    LaunchdLabel, ObservationComponent, Presence, Provider, ProviderEvidence, ProviderEvidenceSet,
    ProviderLogicalKey, ScanScope, ScanWindow, SourceOccurrenceKey, SourceRoot, SourceRootId,
    Subject, TargetPlatform, UnavailableReason,
};

const EXPECTED_JOB_HEADING: &str = "system/org.nixos.nix-gc = {";
const LAUNCHCTL_SERVICE_NOT_FOUND_EXIT: i32 = 113;

// LLM contract: exit 0 plus the expected heading is Present; service-not-found
// is Absent. Other exits, spawn failures, malformed bytes, and filesystem
// errors are typed Unavailable. Normalization retains no raw output or OS text.
pub(crate) fn normalize_launchd(code: Option<i32>, stdout: &[u8]) -> Presence {
    match code {
        Some(LAUNCHCTL_SERVICE_NOT_FOUND_EXIT) => Presence::Absent,
        Some(0) => match std::str::from_utf8(stdout) {
            Ok(output)
                if output
                    .lines()
                    .any(|line| line.trim() == EXPECTED_JOB_HEADING) =>
            {
                Presence::Present
            }
            _ => Presence::Unavailable(UnavailableReason::MalformedEvidence),
        },
        _ => Presence::Unavailable(UnavailableReason::OperationFailed),
    }
}

pub(crate) fn normalize_launchd_output(result: std::io::Result<std::process::Output>) -> Presence {
    match result {
        Ok(output) => normalize_launchd(output.status.code(), &output.stdout),
        Err(_) => Presence::Unavailable(UnavailableReason::InterfaceUnavailable),
    }
}

pub(crate) fn normalize_plist(result: std::io::Result<bool>) -> Presence {
    match result {
        Ok(true) => Presence::Present,
        Ok(false) => Presence::Absent,
        Err(error) => Presence::Unavailable(match error.kind() {
            std::io::ErrorKind::PermissionDenied => UnavailableReason::PermissionDenied,
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                UnavailableReason::TimedOut
            }
            std::io::ErrorKind::InvalidData | std::io::ErrorKind::InvalidInput => {
                UnavailableReason::MalformedEvidence
            }
            _ => UnavailableReason::OperationFailed,
        }),
    }
}

pub(crate) fn launchd_probe() -> Presence {
    normalize_launchd_output(
        std::process::Command::new("/bin/launchctl")
            .args(["print", "system/org.nixos.nix-gc"])
            .output(),
    )
}

pub(crate) fn plist_probe() -> Presence {
    normalize_plist(
        std::path::Path::new("/Library/LaunchDaemons/org.nixos.nix-gc.plist").try_exists(),
    )
}

fn launchd_occurrence() -> DefinitionOccurrence {
    DefinitionOccurrence::new(
        ProviderLogicalKey::Launchd {
            domain: LaunchdDomain::System,
            subject: Subject::System,
            label: LaunchdLabel::new("org.nixos.nix-gc").expect("fixed label is valid"),
        },
        SourceOccurrenceKey::new(SourceRoot::LaunchdPlist(SourceRootId::new(1)), 1),
        CaptureSequence::new(0),
    )
}

pub(crate) fn diagnostic_input() -> Result<DiagnosticInput, InputError> {
    let started = std::time::SystemTime::now();
    let occurrence = launchd_occurrence();
    let evidence = ProviderEvidenceSet::new(vec![
        ProviderEvidence::with_occurrence(
            Provider::NixDarwinLaunchd,
            Subject::System,
            ObservationComponent::Configuration,
            plist_probe(),
            occurrence.clone(),
        )?,
        ProviderEvidence::with_occurrence(
            Provider::NixDarwinLaunchd,
            Subject::System,
            ObservationComponent::Runtime,
            launchd_probe(),
            occurrence,
        )?,
    ])?;
    let elapsed = std::time::SystemTime::now()
        .duration_since(started)
        .unwrap_or_else(|_| std::time::Duration::from_millis(1))
        .max(std::time::Duration::from_millis(1));
    DiagnosticInput::new(
        TargetPlatform::MacOs,
        ScanScope::System,
        ScanWindow::new(started, elapsed).expect("bounded probe window is valid"),
        evidence,
    )
}

#[cfg(test)]
mod tests {
    use nix_maintenance_status::{Presence, UnavailableReason};

    use super::{normalize_launchd, normalize_launchd_output, normalize_plist};

    #[test]
    fn normalizes_launchd_outcomes_without_retaining_raw_output() {
        #[rustfmt::skip]
        let cases: &[(Option<i32>, &[u8], Presence)] = &[
            (Some(0),   b"system/org.nixos.nix-gc = {\n}\n", Presence::Present),
            (Some(113), b"not found", Presence::Absent),
            (Some(1),   b"private", Presence::Unavailable(UnavailableReason::OperationFailed)),
            (Some(0),   b"unexpected", Presence::Unavailable(UnavailableReason::MalformedEvidence)),
            (Some(0),   &[0xff], Presence::Unavailable(UnavailableReason::MalformedEvidence)),
        ];
        for (code, output, expected) in cases {
            assert_eq!(normalize_launchd(*code, output), *expected);
        }
        let failure = std::io::Error::new(std::io::ErrorKind::NotFound, "private");
        assert_eq!(
            normalize_launchd_output(Err(failure)),
            Presence::Unavailable(UnavailableReason::InterfaceUnavailable)
        );
    }

    #[test]
    fn normalizes_plist_presence_and_io_failure() {
        assert_eq!(normalize_plist(Ok(true)), Presence::Present);
        assert_eq!(normalize_plist(Ok(false)), Presence::Absent);
        let failure = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "private");
        assert_eq!(
            normalize_plist(Err(failure)),
            Presence::Unavailable(UnavailableReason::PermissionDenied)
        );
    }
}
