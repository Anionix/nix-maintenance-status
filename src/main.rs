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

        let probe = match std::process::Command::new("/bin/launchctl")
            .args(["print", "system/org.nixos.nix-gc"])
            .output()
        {
            Ok(output) => output,
            Err(error) => {
                eprintln!("error: could not run launchctl: {error}");
                std::process::exit(2);
            }
        };
        let stdout = probe
            .status
            .success()
            .then(|| String::from_utf8_lossy(&probe.stdout).into_owned());
        let plist_exists =
            std::path::Path::new("/Library/LaunchDaemons/org.nixos.nix-gc.plist").exists();

        match nix_maintenance_status::report_from_launchd(stdout.as_deref(), plist_exists) {
            Ok(report) => print!("{report}"),
            Err(_) => {
                eprintln!("error: launchctl returned an unrecognized nix-gc job description");
                std::process::exit(2);
            }
        }
        return;
    }

    eprintln!(
        "error: unknown option: {}\nTry 'nix-maintenance-status --help' for usage.",
        argument.expect("the no-argument case returned above")
    );
    std::process::exit(2);
}
