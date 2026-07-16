# ADR 0002: Official-aligned cross-platform GC inventory boundary

- Status: Accepted for experimental 0.2
- Date: 2026-07-17
- Normative Spec: [#27](https://github.com/Anionix/nix-maintenance-status/issues/27)

## Context

The 0.1 implementation observes one macOS+nix-darwin launchd arrangement. A
plist, loaded job, and unevaluated `nix.gc.automatic` are not the same evidence;
generic Linux scheduler entries are not official Nix mappings. This ADR records
the single typed boundary selected by Wayfinder; ADR 0001 remains historical
0.1 rationale and is superseded here.

Research trail: [#15 asset](https://github.com/Anionix/nix-maintenance-status/blob/6566039f3ec350402a0739e93a6a16adc0461ad8/docs/research/official-scheduler-authority-seams.md), [#20 asset](https://github.com/Anionix/nix-maintenance-status/blob/584c36cbb4ff3906f7e852be9440829b086eb50a/docs/research/reproducible-linux-integration-coverage-tests.md), and [#26 asset](https://github.com/Anionix/nix-maintenance-status/blob/3cde52511aacf4e4f2ed8b8e5ce8873707ca3d2/docs/research/exact-scheduler-contract-pins.md).

## Decision

### Owned report and I/O-free library

```rust
pub fn diagnose(input: DiagnosticInput) -> GcReport;
pub fn render_human(report: &GcReport, detail: HumanDetail) -> String;
```

`DiagnosticInput` is a `Result` from validated platform, finite `ScanScope`,
bounded `ScanWindow`, and typed provider Evidence. `diagnose` is pure,
deterministic, total, and I/O-free; adapters own probes and may construct
normalized Evidence/reasons, never Claims, Coverage, Authority, or rules.

The typed presentation seam is `resolve_human_detail(&GcReport, ExplainSelector) -> Result<HumanDetail, SelectionError>` between CLI parsing and `render_human`; an absent report-local selector emits no partial output.

The graph is `GcReport { scan, coverage, automations, evidence }` with
`GcAutomation { id, subject, provider, claims }`; conclusion-making constructors
are private getters. Fixed Claims are Configuration, Runtime, Consistency,
Schedule, Command, Activity, Runs, LastResult. `EvidenceSet` owns normalized
Evidence and opaque report-local EvidenceIds, never persistence keys or output.

### Claims, Coverage, and privacy

`Claim<T>` pairs `Conclusion<T>` (`Known`/`Unknown`) with Provenance;
`Applicability<T>` is `Applicable`/`NotApplicable`. Provenance references
EvidenceIds and independent AuthorityRole results (`Resolved`, `Unresolved`,
`NotClaimed`, `NotApplicable`); Unknown propagates only to dependent Claims.

Coverage is the leaf matrix `Provider × Subject × ObservationComponent`, with
Discovery, Configuration, Runtime, Schedule, Command, Activity, Runs, and
LastResult components. Leaves are `Covered`, `Unavailable(reason)`, or
`NotApplicable`; aggregates are pure `Complete`, `Partial`, or `Unavailable`.
`Absent`/`PresentEmpty`/`Present` remain distinct; empty can be Complete, while
external identity relevance makes the AllUsers Subject leaf unavailable.

Subjects render only as `system`, `uid:<n>`, or canonical-sort-allocated
`subject:unresolved:<ordinal>`. AllUsers is a bounded local `/etc/passwd`
snapshot retaining CurrentUser, collapsing duplicate UIDs, and checking
start/end stability. NSS, user switching, and explicit privilege elevation
(sudo/su/pkexec) are forbidden; a catalogued official read-only client may
retain OS-installed setuid/setgid behavior. Usernames,
homes, labels, raw paths/commands, stdout/stderr, control characters, and OS
errors are excluded from the report and renderer.

### Claim-scoped Authority Catalog

The non-substitutable roles are `GcOperationSemantics` (Nix command/GC meaning),
`AutomationMapping` (exact nix-darwin/NixOS mapping), and `SchedulerSemantics`
(exact provider contract). The embedded catalog is the only trust root: each
entry has stable family ID, exact pin, full citations, mapping/contract
fingerprint, package/patch IntegrityPin, and lifecycle metadata. Branches,
ranges, prefixes, nearest versions, plugins, caller Authority, and runtime
network resolution are forbidden.

Initial anchors are fixed and independently checked:

- Nix `035f34f13f969cf72ca4ea60369d907972402956`: [`nix-collect-garbage.cc`](https://github.com/NixOS/nix/blob/035f34f13f969cf72ca4ea60369d907972402956/src/nix/nix-collect-garbage/nix-collect-garbage.cc), [`nix-store.cc`](https://github.com/NixOS/nix/blob/035f34f13f969cf72ca4ea60369d907972402956/src/nix/nix-store/nix-store.cc), [`store-gc.cc`](https://github.com/NixOS/nix/blob/035f34f13f969cf72ca4ea60369d907972402956/src/nix/store-gc.cc), and fixed manuals.
- nix-darwin `8c62fba0854ba15c8917aed18894dbccb48a3777`: GC module plus canonical [`launchd/default.nix#L89-L94`](https://github.com/nix-darwin/nix-darwin/blob/8c62fba0854ba15c8917aed18894dbccb48a3777/modules/launchd/default.nix#L89-L94) fingerprint.
- NixOS `e8d924d50a462f89166e31a27bdcbbade35fd8e6`: [`nix-gc.nix`](https://github.com/NixOS/nixpkgs/blob/e8d924d50a462f89166e31a27bdcbbade35fd8e6/nixos/modules/services/misc/nix-gc.nix) plus generated-script [`systemd-lib.nix#L556-L584`](https://github.com/NixOS/nixpkgs/blob/e8d924d50a462f89166e31a27bdcbbade35fd8e6/nixos/lib/systemd-lib.nix#L556-L584).
- Scheduler ContractPins: launchd macOS build `26A5378j`; systemd 261 and
  262~devel; Cronie/anacron; fcron 3.4.0 and 3.4.1. NixOS fixtures use
  Nixpkgs `6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee`; package/patch pins are
  distinct from upstream contracts.

`AutomationMapping` resolves only after the complete normalized artifact
fingerprint matches its pin; a generic scheduler receives only
SchedulerSemantics. Unknown revision retains observations but leaves Authority
Unresolved; `catalog-check` verifies every full-SHA blob and citation.

### Schedules, relations, and CLI

The non-exhaustive Schedule union is provider-native Launchd, Systemd, Cronie,
Anacron, or Fcron, preserving calendar/monotonic, randomization/persistence,
catch-up/timezone, inheritance, and grammar semantics without raw text. A
common projection is display-only. Relations are pure over canonical IDs and
return typed Related, Independent, or Indeterminate results; unknown/self IDs
are typed errors, node findings are separate, and no overall health exists.

The CLI uses deterministic candidate blocks, scan/Coverage header, privacy-safe
Subjects, finite `--scope`/`--explain`, plain UTF-8, no pager/ANSI, and no
JSON/fix/GC flags. Invalid syntax, absent selectors, and unsupported platforms
use normalized stderr/exit 2; help/version probe nothing/exit 0; Complete or
Partial exits 0; wholly Unavailable renders stdout/exit 2. It never asserts
direct evaluation of `nix.gc.automatic`.

### Safety, CI, and migration

All probes are read-only, bounded, no-retry, no-telemetry, no-runtime-network,
no explicit elevation, and no-GC-execution; catalogued read-only clients may
retain OS setuid/setgid, and raw output is discarded after normalization. CI
requires stable Linux, `cargo +1.85.0` MSRV, macOS, flake,
offline catalog-check, exact-identity NixOS VMs, and full-SHA Actions with
`contents: read`.

Fresh-main, non-stacked, near-250-line order is CONTEXT/ADR, report/catalog,
Schedule/macOS, systemd/NixOS, Cronie/anacron/fcron, relations/CLI, CI/flake,
then README/migration. Historical macOS issues point to #27 and cannot form a
second implementation path.

## LLM contract

Valid transitions are `Evidence → Claim(Known|Unknown)` and
`Coverage leaf → aggregate(Complete|Partial|Unavailable)`. Triggers are only
normalized adapter Evidence and pure catalog/relation derivation. Invariants:
Unknown is never Absent, unavailable leaves remain local, Provenance is typed,
Authority is catalog-only, rendering is pure, and no transition performs I/O,
network, telemetry, mutation, explicit elevation, or garbage collection (except
catalogued read-only clients' OS setuid/setgid behavior); this documentation
cannot introduce a second implementation path.
