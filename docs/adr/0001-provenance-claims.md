# ADR 0001: Model diagnostics as provenance-bearing claims

- Status: Accepted
- Date: 2026-07-15

## Context

The 0.1 diagnostic observes a nix-darwin launchd job and plist, then renders a
single enabled/not-detected result. That presentation can overstate the evidence:
a local artifact is not a direct evaluation of `nix.gc.automatic`, and a loaded
job does not prove the persistent Configuration.

The architecture review compared a fixed snapshot classifier, an extensible
proof engine, and a minimal public diagnostic operation. The selected minimal
hybrid keeps the caller-facing operation small while separating platform I/O,
classification, and rendering.

## Decision

### Public diagnostic boundary

The experimental 0.2 library contract will be:

```rust
pub fn diagnose(input: DiagnosticInput) -> GcReport;
pub fn render_human(report: &GcReport, detail: HumanDetail) -> String;
```

`DiagnosticInput::macos(MacOsEvidence)` will wrap macOS-specific evidence.
`MacOsEvidence::new(plist_probe, launchd_probe)` will accept the two core probes,
with nix-darwin version evidence added by a fluent method. A future NixOS adapter
can add another constructor without changing the diagnostic operation.

The library accepts normalized Evidence and performs no I/O. The CLI adapter
owns launchctl execution, filesystem checks, version discovery, and parsing of
external output. Boundary constructors validate ranges and remove control
characters before a value can enter a report.

### Claim model

`GcReport` contains separate, typed Claims for Configuration, Runtime,
Consistency, Activity, Schedule, Command, Runs, and LastResult. Report and Claim
fields are private and exposed through read-only accessors.

- `Probe<T>` distinguishes Observed, Absent, and Unavailable input.
- `Conclusion<T>` distinguishes Known from Unknown output.
- Optional values use `OptionalValue<T>` to distinguish Present from
  NotApplicable; probe failure remains Unknown.
- Provenance records an Evidence class, normalized Observations, an optional
  Authority, and an optional Inference rule.

There is no numerical confidence and no single overall status. Human output
always labels each displayed value as observed, inferred, or unknown.

### Independent Configuration and Runtime evidence

Configuration is derived only from whether the expected launchd plist is
observed. Runtime is derived only from whether launchd reports the job as loaded.
Consistency compares those independent Claims:

| Plist | Launchd job | Configuration | Runtime | Consistency |
| --- | --- | --- | --- | --- |
| Present | Present | Consistent with automatic GC | Loaded | Consistent |
| Present | Absent | Consistent with automatic GC | Not loaded | Inconsistent |
| Absent | Present | Not detected | Loaded | Inconsistent |
| Absent | Absent | Not detected | Not loaded | Consistent |

`Not detected` never means `disabled`. Likewise, an observed plist supports only
the Inference that the artifact is consistent with nix-darwin automatic GC; it
does not prove that `nix.gc.automatic = true` was directly evaluated.

If either core probe is Unknown, Consistency is Unknown. A launchctl exit status
of 113 represents an absent service. Other non-zero statuses, process failures,
and unrecognized output become Unknown instead of being treated as absence.

### Versioned Authority

The diagnostic embeds a small Authority catalog and performs no runtime network
requests. The first versioned entry maps nix-darwin `26.05.8c62fba` to commit
[`8c62fba0854ba15c8917aed18894dbccb48a3777`](https://github.com/nix-darwin/nix-darwin/blob/8c62fba0854ba15c8917aed18894dbccb48a3777/modules/services/nix-gc/default.nix),
whose GC module maps automatic GC to the launchd job and plist.

An unrecognized or unavailable local revision is retained as an Observation,
but the Authority is marked version unknown. It may still support the limited
"consistent with" Inference; it cannot support a direct configuration claim.

### Rendering and process result

Summary output always includes Configuration, Runtime, and Consistency with
Evidence labels. Activity and other optional values are shown only when Present.
`HumanDetail::Explain` additionally renders normalized Observations, Authority
permalinks, Inference rules, and Unknown reasons. Raw launchctl or plist content
is never rendered.

On macOS, the CLI exits successfully when at least one core Claim can be
determined. If Configuration and Runtime are both Unknown, it still renders the
report but exits with status 2. Invalid arguments and unsupported platforms also
use status 2.

## Consequences

- CLI and library consumers can distinguish local facts from upstream-backed
  conclusions without parsing prose.
- Malformed or changing launchctl output degrades to Unknown at the adapter seam
  instead of producing a false negative.
- JSON output and NixOS support can reuse `GcReport`, but their schemas and
  adapters require separate design decisions.
- The 0.1 boolean API will be removed as a clean experimental 0.2 break; the
  package remains unpublished.

## Alternatives not selected

- A single enabled/disabled or overall-health result collapses independent
  evidence and invites false certainty.
- Treating an artifact as direct configuration proof confuses Observation with
  Inference.
- Fetching upstream source at runtime would violate the no-network guarantee and
  make results non-reproducible.
- Rendering raw probe output would expose unstable, potentially sensitive input.
- A dynamic proof graph or provider registry adds interface surface before JSON
  and NixOS provide concrete requirements.
