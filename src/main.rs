mod macos_adapter;

use nix_maintenance_status::{
    Conclusion, ConfigurationState, ConsistencyState, DiagnosticInput, EvidenceClass, GcReport,
    MacOsEvidence, RuntimeState, diagnose,
};

const HELP: &str = "\
Explain the effective status of automated Nix maintenance.\n\n\
Usage: nix-maintenance-status [OPTIONS]\n\n\
Options:\n\
  -h, --help     Print help\n\
  -V, --version  Print version\n\n\
This is a read-only diagnostic; it never runs garbage collection or changes configuration.\n";

fn main() {
    let argument = std::env::args().nth(1);
    if matches!(argument.as_deref(), Some("-h" | "--help")) {
        print!("{HELP}");
        return;
    }
    if matches!(argument.as_deref(), Some("-V" | "--version")) {
        println!("nix-maintenance-status {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    if argument.is_none() {
        if std::env::consts::OS != "macos" {
            eprintln!("error: this initial release currently supports macOS with nix-darwin");
            std::process::exit(2);
        }

        let report = diagnose(DiagnosticInput::macos(MacOsEvidence::new(
            macos_adapter::plist_probe(),
            macos_adapter::launchd_probe(),
        )));
        print!("{}", render_summary(&report));
        if report_exit_code(&report) == 2 {
            std::process::exit(2)
        }
        return;
    }

    eprintln!(
        "error: unknown option: {}\nTry 'nix-maintenance-status --help' for usage.",
        argument.expect("the no-argument case returned above")
    );
    std::process::exit(2);
}

fn render_summary(report: &GcReport) -> String {
    let configuration = match report.configuration().conclusion() {
        Conclusion::Known(ConfigurationState::ConsistentWithNixDarwinAutomaticGc) => {
            "consistent with nix-darwin automatic GC"
        }
        Conclusion::Known(ConfigurationState::NotDetected) => "not detected",
        Conclusion::Known(_) | Conclusion::Unknown(_) => "unknown",
    };
    let runtime = match report.runtime().conclusion() {
        Conclusion::Known(RuntimeState::Loaded) => "loaded",
        Conclusion::Known(RuntimeState::NotLoaded) => "not loaded",
        Conclusion::Known(_) | Conclusion::Unknown(_) => "unknown",
    };
    let consistency = match report.consistency().conclusion() {
        Conclusion::Known(ConsistencyState::Consistent) => "consistent",
        Conclusion::Known(ConsistencyState::Inconsistent) => "inconsistent",
        Conclusion::Known(_) | Conclusion::Unknown(_) => "unknown",
    };
    format!(
        "Nix maintenance status\n\nConfiguration: {configuration} [{}]\nRuntime: {runtime} [{}]\nConsistency: {consistency} [{}]\n",
        evidence_label(report.configuration().provenance().evidence_class()),
        evidence_label(report.runtime().provenance().evidence_class()),
        evidence_label(report.consistency().provenance().evidence_class()),
    )
}

fn evidence_label(class: EvidenceClass) -> &'static str {
    match class {
        EvidenceClass::Observed => "observed",
        EvidenceClass::Inferred => "inferred",
        EvidenceClass::Unknown => "unknown",
    }
}

// LLM contract: the report is rendered first; both core Claims Unknown exits 2,
// while any Known core Claim exits 0. Unknown is never converted to absence.
fn report_exit_code(report: &GcReport) -> i32 {
    if matches!(report.configuration().conclusion(), Conclusion::Unknown(_))
        && matches!(report.runtime().conclusion(), Conclusion::Unknown(_))
    {
        2
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use nix_maintenance_status::{GcPlist, LaunchdJob, Probe, ProbeFailure};

    use super::*;

    #[test]
    fn exits_two_only_when_both_core_claims_are_unknown() {
        let report = diagnose(DiagnosticInput::macos(MacOsEvidence::new(
            Probe::<GcPlist>::Unavailable(ProbeFailure::FileSystemUnavailable),
            Probe::<LaunchdJob>::Unavailable(ProbeFailure::CommandUnavailable),
        )));
        assert_eq!(report_exit_code(&report), 2);
        assert_eq!(
            render_summary(&report),
            "Nix maintenance status\n\nConfiguration: unknown [unknown]\nRuntime: unknown [unknown]\nConsistency: unknown [unknown]\n"
        );
        let report = diagnose(DiagnosticInput::macos(MacOsEvidence::new(
            Probe::<GcPlist>::Unavailable(ProbeFailure::FileSystemUnavailable),
            Probe::<LaunchdJob>::Absent,
        )));
        assert_eq!(report_exit_code(&report), 0);
    }
}
