# Security Policy

## Supported versions

This project has not published a release. Only the current `main` branch is
considered for security fixes during the experimental phase.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability.

Use **Security → Report a vulnerability** in the GitHub repository to submit a
private report. Include the affected revision, platform, reproduction steps,
impact, and any suggested mitigation. Remove unrelated secrets and personal
information from logs before attaching them.

This is a personal project maintained on a best-effort basis and does not offer
a response-time SLA. Reports will be acknowledged and assessed as availability
allows.

## Security expectations

`nix-maintenance-status` is intended to be read-only. Behavior that executes
garbage collection, changes configuration, modifies service state, sends
telemetry, or performs an unexpected network request should be treated as a
security-sensitive regression.
