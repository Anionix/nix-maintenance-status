mod macos_adapter;

use error_stack::ResultExt as _;
use rancor::ResultExt as _;

use nix_maintenance_status::{
    Claim, Conclusion, ConsistencyValue, CoverageAggregate, EvidenceClass, GcReport,
    ObservationValue, Provider, diagnose,
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
            eprintln!("error: this release currently supports macOS with nix-darwin");
            std::process::exit(2);
        }
        let input = match normalized_macos_input() {
            Ok(input) => input,
            Err(_report) => {
                eprintln!("error: macOS evidence could not be normalized");
                std::process::exit(2);
            }
        };
        let report = diagnose(input);
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

#[derive(Debug, thiserror::Error)]
#[error("macOS evidence could not be normalized")]
struct NormalizeMacOsEvidence;

// The CLI adds fixed context but never emits source diagnostics. Library
// callers retain the stable typed InputError contract and no raw probe data.
fn normalized_macos_input()
-> Result<nix_maintenance_status::DiagnosticInput, error_stack::Report<NormalizeMacOsEvidence>> {
    macos_adapter::diagnostic_input()
        .into_trace::<rancor::BoxedError, _>("normalizing macOS evidence")
        .change_context(NormalizeMacOsEvidence)
}

fn presence_text(claim: Option<&Claim<ObservationValue>>) -> (&'static str, EvidenceClass) {
    let Some(claim) = claim else {
        return ("unknown", EvidenceClass::Unknown);
    };
    match claim.conclusion() {
        Conclusion::Known(ObservationValue::Present) => {
            ("present", claim.provenance().evidence_class())
        }
        Conclusion::Known(ObservationValue::PresentEmpty) => {
            ("present empty", claim.provenance().evidence_class())
        }
        Conclusion::Known(ObservationValue::Absent) => {
            ("not detected", claim.provenance().evidence_class())
        }
        Conclusion::Unknown(_) => ("unknown", EvidenceClass::Unknown),
    }
}

fn runtime_text(claim: Option<&Claim<ObservationValue>>) -> (&'static str, EvidenceClass) {
    let (value, class) = presence_text(claim);
    (
        match value {
            "present" | "present empty" => "loaded",
            "not detected" => "not loaded",
            _ => "unknown",
        },
        class,
    )
}

fn consistency_text(claim: Option<&Claim<ConsistencyValue>>) -> (&'static str, EvidenceClass) {
    let Some(claim) = claim else {
        return ("unknown", EvidenceClass::Unknown);
    };
    match claim.conclusion() {
        Conclusion::Known(ConsistencyValue::Consistent) => {
            ("consistent", claim.provenance().evidence_class())
        }
        Conclusion::Known(ConsistencyValue::Inconsistent) => {
            ("inconsistent", claim.provenance().evidence_class())
        }
        Conclusion::Known(_) => ("unknown", EvidenceClass::Unknown),
        Conclusion::Unknown(_) => ("unknown", EvidenceClass::Unknown),
    }
}

fn render_summary(report: &GcReport) -> String {
    let automation = report
        .automations()
        .iter()
        .find(|automation| automation.provider() == Provider::NixDarwinLaunchd);
    let claims = automation.map(|automation| automation.claims());
    let (configuration, configuration_class) =
        presence_text(claims.map(|claims| claims.configuration()));
    let (runtime, runtime_class) = runtime_text(claims.map(|claims| claims.runtime()));
    let (consistency, consistency_class) =
        consistency_text(claims.map(|claims| claims.consistency()));
    format!(
        "Nix maintenance status\n\nConfiguration: {configuration} [{}]\nRuntime: {runtime} [{}]\nConsistency: {consistency} [{}]\n",
        evidence_label(configuration_class),
        evidence_label(runtime_class),
        evidence_label(consistency_class),
    )
}

fn evidence_label(class: EvidenceClass) -> &'static str {
    match class {
        EvidenceClass::Observed => "observed",
        EvidenceClass::Inferred => "inferred",
        EvidenceClass::Unknown => "unknown",
    }
}

// LLM contract: rendering is pure and happens before exit selection. A report
// with no Covered leaf exits 2; any usable Covered leaf exits 0. Unknown is
// never rewritten as Absent, and rendering performs no I/O or mutation.
fn report_exit_code(report: &GcReport) -> i32 {
    match report.coverage().aggregate() {
        CoverageAggregate::Unavailable => 2,
        CoverageAggregate::Complete | CoverageAggregate::Partial => 0,
        _ => 2,
    }
}

#[cfg(test)]
mod tests {
    use nix_maintenance_status::{
        DiagnosticInput, ObservationComponent, Presence, ProviderEvidence, ProviderEvidenceSet,
        ScanScope, ScanWindow, Subject, TargetPlatform, UnavailableReason,
    };

    use super::*;

    fn input(config: Presence, runtime: Presence) -> DiagnosticInput {
        DiagnosticInput::new(
            TargetPlatform::MacOs,
            ScanScope::System,
            ScanWindow::new(std::time::UNIX_EPOCH, std::time::Duration::from_secs(1)).unwrap(),
            ProviderEvidenceSet::new(vec![
                ProviderEvidence::new(
                    Provider::NixDarwinLaunchd,
                    Subject::System,
                    ObservationComponent::Configuration,
                    config,
                )
                .unwrap(),
                ProviderEvidence::new(
                    Provider::NixDarwinLaunchd,
                    Subject::System,
                    ObservationComponent::Runtime,
                    runtime,
                )
                .unwrap(),
            ])
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn exits_two_only_when_no_core_leaf_is_usable() {
        let report = diagnose(input(
            Presence::Unavailable(UnavailableReason::PermissionDenied),
            Presence::Unavailable(UnavailableReason::InterfaceUnavailable),
        ));
        assert_eq!(report_exit_code(&report), 2);
        let report = diagnose(input(Presence::Present, Presence::Absent));
        assert_eq!(report_exit_code(&report), 0);
    }
}
