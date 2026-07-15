# nix-maintenance-status

[English](README.md) | [日本語](README.ja.md)

[![CI](https://github.com/Anionix/nix-maintenance-status/actions/workflows/ci.yml/badge.svg)](https://github.com/Anionix/nix-maintenance-status/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Status: experimental](https://img.shields.io/badge/status-experimental-orange.svg)](#project-status)

`nix-maintenance-status` is a read-only diagnostic that connects automated Nix
maintenance configuration to the operating-system job that actually runs it.

It exists because a declarative option, the generated launchd job, and the Nix
command are otherwise easy to mistake for one feature living in one place.

> [!IMPORTANT]
> This is an independent personal project. It is not an official Nix, NixOS, or
> nix-darwin project and is not affiliated with their maintainers.

## Project status

This repository contains an experimental 0.1-series implementation. The CLI
output, Rust library API, and supported evidence sources may change without a
compatibility guarantee.

| Platform | Configuration layer | Runtime layer | Status |
| --- | --- | --- | --- |
| macOS | nix-darwin | launchd | Experimental |
| NixOS/Linux | NixOS modules | systemd | Planned |

## Quick start

Run the current default branch directly with Nix:

```console
nix run github:Anionix/nix-maintenance-status
```

Or run a local checkout:

```console
git clone https://github.com/Anionix/nix-maintenance-status.git
cd nix-maintenance-status
nix run .
```

Example output:

```text
Nix maintenance status

Configuration: consistent with nix-darwin automatic GC [inferred]
Runtime: loaded [observed]
Consistency: consistent [inferred]
```

## Safety and privacy

The diagnostic is deliberately read-only. At runtime it only:

- runs `launchctl print system/org.nixos.nix-gc`; and
- checks whether `/Library/LaunchDaemons/org.nixos.nix-gc.plist` exists.

It does not run garbage collection, edit Nix configuration, change launchd,
send telemetry, or make network requests. `nix run github:...` uses the network
to obtain the source and dependencies before the diagnostic starts.

## How it works

The first supported path crosses three separate layers:

1. Nix provides `nix-collect-garbage`.
2. nix-darwin provides the `nix.gc.automatic` module option.
3. launchd loads and schedules `org.nixos.nix-gc`.

The tool reads runtime evidence from launchd and presents those layers in one
status report. It never evaluates or changes the user's nix-darwin
configuration.

## Evidence model

The report distinguishes what the system proves from what the tool infers:

| Classification | Meaning | Example |
| --- | --- | --- |
| Observed | Read directly from the inspected artifacts | plist or loaded-job presence |
| Inferred | Conclusion derived from observed evidence | standard plist is consistent with automatic GC |
| Unknown | Not exposed by the inspected interface | exact `.nix` source file |

launchd exposes the generated job but does not identify the original Nix source
file or module assignment. A detected standard plist is therefore marked
`inferred`; its absence is observed and reported as `not detected`.

## Current limitations

- Only macOS with nix-darwin is supported.
- Parsing relies on the human-readable output of `launchctl print`.
- Exact option provenance and the next wall-clock execution time are unavailable.

## Roadmap

- Add NixOS/systemd support.
- Add structured JSON output.
- Improve schedule rendering.
- Report exact module provenance where an authoritative source is available.

The roadmap is directional and does not constitute a delivery commitment.

## Development

Enter the Nix development environment and run the quality gates:

```console
nix develop
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
nix flake check
```

The Rust crate currently has no third-party dependencies.

## Contributing and security

Small, focused issues and pull requests are welcome. Read
[CONTRIBUTING.md](CONTRIBUTING.md) before contributing. Report suspected
security problems privately as described in [SECURITY.md](SECURITY.md).

## License

Licensed under the [MIT License](LICENSE).
