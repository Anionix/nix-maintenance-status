use std::fmt::Write;

mod diagnostic;

pub use diagnostic::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LastResult {
    NeverRun,
    Success,
    Failure(i32),
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaintenanceStatus {
    pub job: String,
    pub configured: bool,
    pub loaded: bool,
    pub running: bool,
    pub runs: Option<u64>,
    pub last_result: LastResult,
    pub command: Option<String>,
    pub schedule: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError;

// LLM contract: valid launchd text produces a loaded configuration; `running`
// implies `loaded`. An absent job is not running, and Configuration then follows
// the independent plist observation. Failed probes belong to the typed API.
pub fn parse_launchd_status(input: &str) -> Result<MaintenanceStatus, ParseError> {
    let job = input
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("system/")?.strip_suffix(" = {"))
        .ok_or(ParseError)?
        .to_owned();

    let value_for = |key: &str| {
        input
            .lines()
            .map(str::trim)
            .find_map(|line| line.strip_prefix(key)?.strip_prefix(" = "))
    };

    let state = value_for("state");
    let running = state == Some("running");
    let runs = value_for("runs").and_then(|value| value.parse().ok());
    let last_result = match value_for("last exit code") {
        Some("(never exited)") => LastResult::NeverRun,
        Some("0") => LastResult::Success,
        Some(value) => value
            .parse()
            .map(LastResult::Failure)
            .unwrap_or(LastResult::Unknown),
        None => LastResult::Unknown,
    };

    let command = input.lines().map(str::trim).find_map(|line| {
        if !line.contains("nix-collect-garbage") {
            return None;
        }
        Some(
            line.split_once("exec ")
                .map(|(_, command)| command)
                .unwrap_or(line)
                .trim()
                .to_owned(),
        )
    });

    let calendar_value = |key: &str| {
        input.lines().map(str::trim).find_map(|line| {
            let value = line.strip_prefix(&format!("\"{key}\" => "))?;
            value.parse::<u8>().ok()
        })
    };
    let schedule = match (
        calendar_value("Weekday"),
        calendar_value("Hour"),
        calendar_value("Minute"),
    ) {
        (Some(weekday), Some(hour), Some(minute)) => {
            Some(format!("weekday {weekday} at {hour:02}:{minute:02}"))
        }
        _ => None,
    };

    Ok(MaintenanceStatus {
        job,
        configured: true,
        loaded: true,
        running,
        runs,
        last_result,
        command,
        schedule,
    })
}

pub fn diagnose_launchd(
    launchctl_output: Option<&str>,
    plist_exists: bool,
) -> Result<MaintenanceStatus, ParseError> {
    match launchctl_output {
        Some(output) => parse_launchd_status(output),
        None => Ok(MaintenanceStatus {
            job: "org.nixos.nix-gc".to_owned(),
            configured: plist_exists,
            loaded: false,
            running: false,
            runs: None,
            last_result: LastResult::Unknown,
            command: None,
            schedule: None,
        }),
    }
}

pub fn render_human(status: &MaintenanceStatus) -> String {
    let mut output = String::from("Nix maintenance status\n\n");
    let enabled = if status.configured {
        "enabled"
    } else {
        "not detected"
    };
    let runtime = match (status.loaded, status.running) {
        (true, true) => "loaded, running",
        (true, false) => "loaded, idle",
        (false, _) => "not loaded",
    };
    let last_result = match status.last_result {
        LastResult::NeverRun => "never run since the job was loaded".to_owned(),
        LastResult::Success => "success".to_owned(),
        LastResult::Failure(code) => format!("failed with exit code {code}"),
        LastResult::Unknown => "unknown".to_owned(),
    };

    writeln!(output, "Garbage collection: {enabled}").expect("writing to a String cannot fail");
    let configuration = if status.configured {
        "nix-darwin nix.gc.automatic (inferred)"
    } else {
        "not detected (observed)"
    };
    writeln!(output, "Configuration: {configuration}").expect("writing to a String cannot fail");
    writeln!(output, "Runtime job: {} ({runtime})", status.job)
        .expect("writing to a String cannot fail");
    if let Some(schedule) = &status.schedule {
        writeln!(output, "Schedule: {schedule}").expect("writing to a String cannot fail");
    }
    if let Some(command) = &status.command {
        writeln!(output, "Command: {command}").expect("writing to a String cannot fail");
    }
    if let Some(runs) = status.runs {
        writeln!(output, "Runs since load: {runs}").expect("writing to a String cannot fail");
    }
    writeln!(output, "Last result: {last_result}").expect("writing to a String cannot fail");
    output.push_str(
        "\nLayer note: Nix GC itself is provided by Nix; periodic execution on macOS is provided by nix-darwin through launchd.\n",
    );
    output
}

pub fn report_from_launchd(
    launchctl_output: Option<&str>,
    plist_exists: bool,
) -> Result<String, ParseError> {
    diagnose_launchd(launchctl_output, plist_exists).map(|status| render_human(&status))
}
