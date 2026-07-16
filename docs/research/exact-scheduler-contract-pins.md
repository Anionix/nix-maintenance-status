# Exact scheduler ContractPins for the NixOS VM identities

Status: primary-source research snapshot, 2026-07-17

This note resolves [Issue #26](https://github.com/Anionix/nix-maintenance-status/issues/26).
It identifies the exact scheduler contracts used by the reproducible NixOS VM
fixtures. It does not change the Rust API, flake, workflow, README, lockfile,
or Provider Catalog. Linux execution was not available on this macOS host, so
the VM result is source-specified and must be verified by the future CI gate.

## Result

The Provider Catalog must carry both the source identities already used by the
Schedule decision and the exact identities used by the VM fixtures:

| provider | VM fixture ContractPin | existing #19 ContractPin | policy |
| --- | --- | --- | --- |
| systemd | upstream `v261`, peeled commit [`de9dbc37ad4aa637e200ac02a0545095997055df`](https://github.com/systemd/systemd/tree/de9dbc37ad4aa637e200ac02a0545095997055df) | `262~devel`, [`07a9d1f929f7ae2c4d4fbbdb0d307d993e83be8e`](https://github.com/systemd/systemd/tree/07a9d1f929f7ae2c4d4fbbdb0d307d993e83be8e) | retain both; never substitute the nearest version |
| fcron | upstream `ver3_4_0`, commit [`8198d4b90690fb0f53cca931b6e9bb6d4b9e6f83`](https://github.com/yo8192/fcron/tree/8198d4b90690fb0f53cca931b6e9bb6d4b9e6f83) | `ver3_4_1`, [`a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130`](https://github.com/yo8192/fcron/tree/a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130) | retain both; never substitute the nearest version |

The fixture's version is an identity, not merely a display string. A property
is covered only when its exact ContractPin and the package actually executed by
the VM are both known. A known normalized observation remains useful when its
Authority is unresolved; it must be tagged `Unresolved`, not promoted to
officiality or discarded as if the scheduler were absent.

## Three identities that must not be collapsed

* **Fixture identity** is the package and module selected by the locked Nixpkgs
  revision. It proves what the disposable VM was intended to execute.
* **SchedulerSemantics ContractPin** is the upstream source revision whose
  grammar, timing, runtime, and query behavior are authoritative for a provider.
* **AutomationMapping Authority** is the pinned Nix/NixOS mapping that can
  attribute a definition to official Nix GC. A systemd timer or fcron entry by
  itself is only an observation.

The three roles remain independent `GcCommandSemantics`, `AutomationMapping`,
and `SchedulerSemantics` claims. A source archive hash is a `SourcePin`; it is
not a Git commit and does not prove that another tag has the same contract.

## Fixture source pins

The reproducible research locks Nixpkgs to
[`6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee`](https://github.com/NixOS/nixpkgs/tree/6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee).
The package expressions are the fixture's package-level source evidence:

* systemd [`default.nix`](https://github.com/NixOS/nixpkgs/blob/6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee/pkgs/os-specific/linux/systemd/default.nix#L197-L236)
  declares `version = "261"`, fetches upstream tag `v261`, and pins Nix's
  fixed-output hash to `sha256-6IB1ZEQqQ0impwBhCaLZAEgMVkVFU61JDVlGotxNzGQ=`.
  The annotated tag object is `102d5065bc82a875cfa0f6fcae6a5bda651cbf0a` and
  peels to the ContractPin commit shown above. Nixpkgs applies its listed
  compatibility patches; those patches are part of the fixture identity and
  are not silently treated as upstream source equivalence.
* fcron [`package.nix`](https://github.com/NixOS/nixpkgs/blob/6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee/pkgs/by-name/fc/fcron/package.nix#L12-L24)
  declares `version = "3.4.0"` and fetches the official archive
  `http://fcron.free.fr/archives/fcron-3.4.0.src.tar.gz` with Nix hash
  `sha256-9Of8VTzdcP9LO2rJE4s7fP+rkZi4wmbZevCodQbg4bU=`. The archive is the
  Nix SourcePin; the upstream Git tag commit above is the separate
  SchedulerSemantics ContractPin. The Nixpkgs `relative-fcronsighup.patch`
  changes executable lookup, not the schedule grammar; it remains part of the
  package identity and is not a reason to claim 3.4.1 compatibility; the
  [patch](https://github.com/NixOS/nixpkgs/blob/6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee/pkgs/by-name/fc/fcron/relative-fcronsighup.patch)
  is explicitly part of that boundary.

NixOS module identity is also pinned to the same Nixpkgs revision. The fcron
module provisions the daemon, spool, access files, wrappers, and system table
([module](https://github.com/NixOS/nixpkgs/blob/6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee/nixos/modules/services/scheduling/fcron.nix#L88-L176)).
The official NixOS GC mapping is a separate authority at
[`nix-gc.nix`](https://github.com/NixOS/nixpkgs/blob/6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee/nixos/modules/services/misc/nix-gc.nix#L20-L103);
its `nix-gc` service, timer, calendar, randomized delay, persistence, and
`nix-collect-garbage` command are not inferred from a generic fixture job.

## systemd 261 contract

The exact ContractPin files are the upstream v261 blobs:

* [`systemd.timer.xml`](https://github.com/systemd/systemd/blob/de9dbc37ad4aa637e200ac02a0545095997055df/man/systemd.timer.xml)
  defines the timer-to-unit relationship, monotonic directives
  (`OnActiveSec`, `OnBootSec`, `OnStartupSec`, `OnUnitActiveSec`, and
  `OnUnitInactiveSec`), calendar directives, trigger OR semantics, persistence,
  accuracy, randomized delay, wake behavior, and catch-up behavior.
* [`systemd.time.xml`](https://github.com/systemd/systemd/blob/de9dbc37ad4aa637e200ac02a0545095997055df/man/systemd.time.xml)
  is the exact calendar and time-span grammar used by the timer parser.
* [`systemctl.xml`](https://github.com/systemd/systemd/blob/de9dbc37ad4aa637e200ac02a0545095997055df/man/systemctl.xml)
  defines read-only `list-timers` and `show` output and the `--user` scope.
  The probe normalizes selected fields and never stores command output.
* [`org.freedesktop.systemd1.xml`](https://github.com/systemd/systemd/blob/de9dbc37ad4aa637e200ac02a0545095997055df/man/org.freedesktop.systemd1.xml)
  is the D-Bus interface authority when a typed manager query is used instead
  of the command adapter.

The fixture may therefore assert the following without relying on 262~devel:

| observed seam | v261 property covered | fixture limit |
| --- | --- | --- |
| timer unit and matching service | a `.timer` activates its configured unit; default name is the matching service | inert test service only; no GC execution |
| calendar and monotonic fields | each exact v261 directive is parsed; multiple directives trigger on any expression | no conversion to cron or launchd syntax |
| configuration query | selected `list-timers`/`show` fields normalize to owned values | output, warnings, paths, and errors are discarded |
| runtime query | manager can report loaded/active state for system and user scopes | inactive user manager is unavailable, not global absence |
| sleep/persistence/delay fields | fields are preserved when present in the v261 contract | no claim about behavior not exercised by the VM |

The VM must assert package identity before scheduler assertions (for example,
the `systemctl --version` major is 261). It must not use the 262~devel docs to
interpret a 261 observation. Properties introduced after v261, or properties
whose behavior depends on a Nixpkgs patch not covered by this pin, are
`Unknown(AuthorityUnresolved)` until a matching catalog entry exists.

Generic systemd evidence has `AutomationMapping = NotClaimed`. Only the exact
NixOS `nix-gc.nix` mapping can produce an official Nix GC attribution, and the
fixture deliberately uses inert commands. A loaded timer proves Runtime, not
that Nix GC is configured or enabled.

## fcron 3.4.0 contract

The exact upstream ContractPin files are:

* [`fcrontab.5.sgml`](https://github.com/yo8192/fcron/blob/8198d4b90690fb0f53cca931b6e9bb6d4b9e6f83/doc/en/fcrontab.5.sgml)
  defines table entries, absolute fields, period families, wildcard/range/
  step grammar, inheritance, `dayand`/`dayor`, shortcuts, and timing-affecting
  options such as `bootrun`, `runfreq`, `first`, `jitter`, `random`,
  `timezone`, `tzdiff`, `serial`, `exesev`, `until`, `strict`, `volatile`, and
  reboot/resume options.
* [`fcrontab.1.sgml`](https://github.com/yo8192/fcron/blob/8198d4b90690fb0f53cca931b6e9bb6d4b9e6f83/doc/en/fcrontab.1.sgml)
  defines the user/system table boundary and the read-only `-l` listing. The
  adapter does not invoke edit, install, remove, or reinstall operations.
* [`fcron.8.sgml`](https://github.com/yo8192/fcron/blob/8198d4b90690fb0f53cca931b6e9bb6d4b9e6f83/doc/en/fcron.8.sgml)
  defines daemon startup, config/spool selection, queue limits, first sleep,
  and runtime signals. These are scheduler semantics, not Nix mapping.
* [`fcrondyn.1.sgml`](https://github.com/yo8192/fcron/blob/8198d4b90690fb0f53cca931b6e9bb6d4b9e6f83/doc/en/fcrondyn.1.sgml)
  defines read-only job listing and status fields. Only listing/status commands
  are allowed in the fixture.

The NixOS fcron module fixes `/etc/fcron.conf`, `/var/spool/fcron`, the fcron
system user, wrappers, and `fcron.service` ([module](https://github.com/NixOS/nixpkgs/blob/6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee/nixos/modules/services/scheduling/fcron.nix#L109-L176)).
The VM identity check must establish fcron `3.4.0` from the package, then use
the exact 3.4.0 grammar and query contract. The fcron daemon and table may be
present while a user query is permission-denied; that is `Unavailable` for the
affected leaf, not provider absence.

The 3.4.1 docs are not interchangeable. The upstream comparison shows changes
to [`fcrondyn.1.sgml`](https://github.com/yo8192/fcron/compare/8198d4b90690fb0f53cca931b6e9bb6d4b9e6f83...a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130),
including command quoting guidance and an additional `ST` status field. The
3.4.0 parser and renderer must not accept or require those 3.4.1 fields. This
is sufficient evidence to reject nearest-version substitution even where the
main table grammar appears unchanged.

## Observation boundaries and property matrix

| provider | configuration | runtime | schedule | activity/result | unavailable boundary |
| --- | --- | --- | --- | --- | --- |
| systemd 261 | unit files or selected manager properties | system/user manager state via read-only `show`/D-Bus | exact v261 timer/calendar fields | only fields explicitly exposed by the selected query; no journal scraping | command unavailable, permission denied, malformed/non-UTF-8 output, or manager absent |
| fcron 3.4.0 | effective table, config, spool metadata | daemon reachability and query status | normalized 3.4.0 entry/options | listing fields only; no execution and no guessed last result | denied table/spool, daemon unavailable, malformed table/query, or unknown inherited option |

`Present` means a validated definition or manager response was observed;
`Absent` means the exact authoritative location was readable and empty;
`Unavailable` means the location or command could not be safely concluded.
Package absence and empty scheduler inventory are different observations.
An unreadable user manager never establishes that the user has no automation.

Raw stdout, stderr, command paths, environment, account names, and OS error
strings are discarded at the adapter boundary. Normalized fields may be kept
only after UTF-8, range, cardinality, and resource-budget validation. No probe
uses network access, privilege escalation, scheduler writes, or GC execution.

## Compatibility and CI decision

Use the two emulated `runNixOSTest` derivations from the completed Linux
integration research, but make the scheduler-catalog VM assert the exact
fixture identities before checking properties:

1. evaluate the locked Nixpkgs package expressions and preserve their
   SourcePin;
2. in the VM, confirm systemd major `261` and fcron `3.4.0` using normalized
   version probes;
3. run only assertions listed in the v261 and 3.4.0 property matrix above;
4. retain parser fixtures for malformed, permission, non-UTF-8, and command
   failure states; and
5. keep the native Linux smoke and existing macOS smoke unchanged.

The VM is the authoritative integration fixture. A local macOS run is not a
negative result: it is simply `NotExecuted` pending Linux CI. Containers and
the host's scheduler packages cannot replace this identity-controlled VM.

If an exact revision cannot be established, the safe result is:

* normalized configuration/runtime/schedule observations remain in the report;
* the affected SchedulerSemantics or AutomationMapping claim is
  `Unresolved(AuthorityRevisionUnknown)`;
* no official Nix GC conclusion or cross-version equivalence is emitted; and
* CI fails the ContractPin gate rather than silently selecting the nearest tag.

This preserves useful diagnostics while keeping the official trust boundary
strict.

## Decision and handoff

Carry exact entries for systemd 261, systemd 262~devel, fcron 3.4.0, and fcron
3.4.1 in the catalog. The `SourcePin` and `ContractPin` fields must be checked
independently; `IntegrityPin` must cover the package source and any documented
Nixpkgs patch set. The final 0.2 Spec may claim CI coverage for the VM identities
only after the version assertions and exact blob links are present.

No code, README, ADR, flake, workflow, lockfile, generated file, tag, release,
binary, or crates.io package was changed in this research.
