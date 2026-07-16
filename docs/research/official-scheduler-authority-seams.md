# Official scheduler authorities and read-only observation seams

Status: research snapshot, 2026-07-16

This note identifies what an offline diagnostic can observe without claiming
more than the owning upstream source supports. It records source facts, not the
final 0.2 API.

## Method and fixed sources

Only upstream manuals, source repositories, and manuals shipped by the local OS
were used.

| Authority | Fixed point used |
| --- | --- |
| Nix | [`035f34f13f969cf72ca4ea60369d907972402956`](https://github.com/NixOS/nix/tree/035f34f13f969cf72ca4ea60369d907972402956) |
| Nixpkgs/NixOS | [`e8d924d50a462f89166e31a27bdcbbade35fd8e6`](https://github.com/NixOS/nixpkgs/tree/e8d924d50a462f89166e31a27bdcbbade35fd8e6) |
| nix-darwin research snapshot | [`a4cf1d10853b0d2be19b9eca35d749e201d70b55`](https://github.com/nix-darwin/nix-darwin/tree/a4cf1d10853b0d2be19b9eca35d749e201d70b55) |
| Locally active nix-darwin | [`8c62fba0854ba15c8917aed18894dbccb48a3777`](https://github.com/nix-darwin/nix-darwin/tree/8c62fba0854ba15c8917aed18894dbccb48a3777) |
| Apple open-source launchd | [`d448a1c8f70a61202f8705f94337f686b87c30c4`](https://github.com/apple-oss-distributions/launchd/tree/d448a1c8f70a61202f8705f94337f686b87c30c4) |
| systemd | [`07a9d1f929f7ae2c4d4fbbdb0d307d993e83be8e`](https://github.com/systemd/systemd/tree/07a9d1f929f7ae2c4d4fbbdb0d307d993e83be8e) |
| Cronie/anacron | [`5f9f16b5663becefdd0dd70df31c0ef5ac36f943`](https://github.com/cronie-crond/cronie/tree/5f9f16b5663becefdd0dd70df31c0ef5ac36f943) |
| fcron | [`a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130`](https://github.com/yo8192/fcron/tree/a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130) |

The macOS checks ran without privilege elevation on macOS 27.0 build
`26A5378j`, Darwin 27.0.0. The shipped manuals were
`/usr/share/man/man5/launchd.plist.5` (SHA-256 `1c5f5041c1d3492988bfa6f9dc6d969dfd072d20af2703c28d9a8f6ed6aaadcb`)
and `/usr/share/man/man1/launchctl.1` (SHA-256
`cf8752dd8eb8c3370c7d03b333430aa68a665c907c475ea407cb1b6542083ae2`).
Apple's published guide confirms the daemon/agent plist locations and calendar
wildcard behavior, while referring readers to those shipped manuals for the
complete contract ([Apple: creating launchd jobs](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)).

## Authority boundary

| Role | Owner | What it can establish |
| --- | --- | --- |
| `GcCommandSemantics` | Nix | What `nix-collect-garbage` does and the risk of its options |
| `AutomationMapping` | NixOS or nix-darwin | Which scheduler artifact an official module generates |
| `SchedulerSemantics` | systemd or Apple | How a generated timer/job is scheduled and represented at runtime |

A scheduler job that merely invokes a Nix executable has command and scheduler
authorities. It does **not** have an official `AutomationMapping` unless its
normalized evidence matches a versioned NixOS or nix-darwin mapping.

## Nix command semantics

The Nix manual defines `nix-collect-garbage` as mostly an alias of
`nix-store --gc`: it deletes unreachable store objects. `--delete-old` and
`--delete-older-than` first remove profile generations and can affect profiles
belonging to other users; removing prior configurations makes rollback
impossible ([fixed Nix manual](https://github.com/NixOS/nix/blob/035f34f13f969cf72ca4ea60369d907972402956/doc/manual/source/command-ref/nix-collect-garbage.md)).

- It may recognize a normalized executable ending in `/bin/nix-collect-garbage`
  and validated arguments, but must never execute it.
- `nix --version` identifies a release string, not the exact source revision of
  a possibly patched build. A version string alone cannot authenticate the
  local executable against the fixed Nix source.
- Shell wrappers and arbitrary scheduler command strings remain Observations;
  substring matching must not promote them to an official automation mapping.

## NixOS mapping

At the fixed Nixpkgs revision, `nix.gc.automatic` defaults to false. When true,
the module creates `nix-gc.timer`; `nix-gc.service` runs the configured Nix
package's `nix-collect-garbage`, and `dates`, `randomizedDelaySec`, and
`persistent` feed the timer ([GC module](https://github.com/NixOS/nixpkgs/blob/e8d924d50a462f89166e31a27bdcbbade35fd8e6/nixos/modules/services/misc/nix-gc.nix)).
NixOS translates a service's non-empty `startAt` list into a same-named timer
whose `OnCalendar` value is that list
([systemd module](https://github.com/NixOS/nixpkgs/blob/e8d924d50a462f89166e31a27bdcbbade35fd8e6/nixos/modules/system/boot/systemd.nix#L792-L796)).

| Claim | Read-only seam | Normalized interpretation |
| --- | --- | --- |
| Revision | `nixos-version --revision` | Exact lowercase 40-hex revision; command absence/failure/malformed output stays Unknown |
| Configuration | Effective `nix-gc.service` and `nix-gc.timer` definitions | Matching versioned units support an Inference, not direct observation of `nix.gc.automatic` |
| Runtime | systemd manager state for both units | Loaded/active states remain independent from persistent mapping |
| Schedule | Effective timer properties | Preserve systemd calendar syntax and timer policy; do not coerce it to launchd fields |
| Command | Effective service `ExecStart` | Recognize only a validated executable/argv; retain overrides as evidence |
| Activity/LastResult | Effective service properties | Normalize typed manager properties; missing or inaccessible properties are Unknown |
| Runs | No NixOS module counter | Do not substitute restart counts or a partial journal count for lifetime runs |

`nixos-version --revision` emits the built Nixpkgs revision and exits non-zero
when it is unknown ([script](https://github.com/NixOS/nixpkgs/blob/e8d924d50a462f89166e31a27bdcbbade35fd8e6/nixos/modules/installer/tools/nixos-version.sh),
[manual](https://github.com/NixOS/nixpkgs/blob/e8d924d50a462f89166e31a27bdcbbade35fd8e6/nixos/modules/installer/tools/manpages/nixos-version.8)).
The underlying NixOS revision is nullable, so unavailable provenance is an
expected state, not malformed configuration
([version module](https://github.com/NixOS/nixpkgs/blob/e8d924d50a462f89166e31a27bdcbbade35fd8e6/nixos/modules/misc/version.nix)).

Unit names alone are insufficient: administrator drop-ins, replacement units,
or manually created units can use the same names. The adapter must inspect the
effective configuration and retain override provenance. Detailed systemd
property, privilege, and absence contracts are recorded in the systemd section.

## nix-darwin mapping and revision

The current research snapshot and the locally active revision have the same
relevant mapping: `nix.gc.automatic` creates `launchd.daemons.nix-gc`, runs the
configured Nix package's `nix-collect-garbage`, disables `RunAtLoad`, and maps
`nix.gc.interval` to `StartCalendarInterval`
([current snapshot](https://github.com/nix-darwin/nix-darwin/blob/a4cf1d10853b0d2be19b9eca35d749e201d70b55/modules/services/nix-gc/default.nix),
[active revision](https://github.com/nix-darwin/nix-darwin/blob/8c62fba0854ba15c8917aed18894dbccb48a3777/modules/services/nix-gc/default.nix)).
The service always runs as root.

The launchd module defaults the label to `org.nixos.nix-gc`, uses that label as
the plist filename, and wraps the configured command in
`/bin/sh -c '/bin/wait4path /nix/store && exec …'`. Both the label prefix and an
individual service label are overridable
([launchd generation](https://github.com/nix-darwin/nix-darwin/blob/8c62fba0854ba15c8917aed18894dbccb48a3777/modules/launchd/default.nix#L10-L12),
[label and argv](https://github.com/nix-darwin/nix-darwin/blob/8c62fba0854ba15c8917aed18894dbccb48a3777/modules/launchd/default.nix#L89-L107)).
Therefore absence of `/Library/LaunchDaemons/org.nixos.nix-gc.plist` means only
"the default artifact was not detected", never "`nix.gc.automatic = false`".

`darwin-version --darwin-revision` reads the active system's embedded metadata,
prints the full revision, and exits non-zero when unknown
([probe source](https://github.com/nix-darwin/nix-darwin/blob/8c62fba0854ba15c8917aed18894dbccb48a3777/pkgs/nix-tools/darwin-version.sh)).
The human label is only a `mkDefault`, while `system.darwinRevision` is the
nullable source revision
([version module](https://github.com/nix-darwin/nix-darwin/blob/8c62fba0854ba15c8917aed18894dbccb48a3777/modules/system/version.nix)).
The revision, not the label, is the catalog key.

## launchd observation seams

| Claim | Preferred read-only seam | Present / Absent / Unavailable |
| --- | --- | --- |
| Configuration | Existence and parsed fields of the generated plist | Valid expected plist / path missing / I/O or plist failure |
| Runtime | Deprecated `SMJobCopyDictionary`, or compatibility `launchctl print` | Job dictionary / documented null or local exit 113 / framework, spawn, permission, or unrecognized response |
| Schedule | Plist `StartCalendarInterval` | Valid dictionary/list / field absent / invalid plist or out-of-range value |
| Command | Plist `ProgramArguments` | Valid argv/template / field absent / invalid or unsafe structure |
| Activity | Runtime `state` or process evidence | Known state / not loaded is NotApplicable / unstable or missing field is Unknown |
| Runs | Runtime `runs` field | Valid non-negative integer / not loaded is NotApplicable / missing or malformed is Unknown |
| LastResult | Runtime `last exit` field | Typed exit/signal/never-run / not loaded is NotApplicable / missing or malformed is Unknown |

The plist is the stronger Configuration, Schedule, and Command seam. The
recorded `launchd.plist(5)` manual defines `Program`/`ProgramArguments`, multiple
calendar dictionaries, wildcards, and ranges: Minute 0–59, Hour 0–23, Day 1–31,
Weekday 0–7, and Month 1–12. Apple's guide confirms that a calendar event missed
during sleep runs on wake
([fixed command schema](https://github.com/apple-oss-distributions/launchd/blob/d448a1c8f70a61202f8705f94337f686b87c30c4/man/launchd.plist.5#L145-L155),
[fixed calendar schema](https://github.com/apple-oss-distributions/launchd/blob/d448a1c8f70a61202f8705f94337f686b87c30c4/man/launchd.plist.5#L256-L273),
[Apple scheduling guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/ScheduledJobs.html)).
nix-darwin additionally rejects an empty interval list and duplicate entries
and encodes the same ranges
([nix-darwin type](https://github.com/nix-darwin/nix-darwin/blob/8c62fba0854ba15c8917aed18894dbccb48a3777/modules/launchd/types.nix)).

The shipped `launchctl(1)` manual says anyone may query the privileged system
domain; root is required for modifications. It also says `launchctl print`
includes origin, current state, execution context, and last exit status, but
explicitly warns that its output is **not an API** and may change without
warning. Thus Activity, Runs, and LastResult parsers are OS-build compatibility
adapters, not portable Apple contracts.
Apple documents deprecated `SMJobCopyDictionary` as returning a job dictionary
or null when the label is not found; it is a narrower loaded-presence seam, not
a source for the undocumented `print` fields
([Service Management API](https://developer.apple.com/documentation/servicemanagement/smjobcopydictionary%28_%3A_%3A%29)).

On the recorded build, an unprivileged query of the loaded
`system/org.nixos.nix-gc` returned exit 0 and normalized fields for state, runs,
last exit, command, and calendar trigger. A missing service returned exit 113.
That 113 meaning is empirical and undocumented; other non-zero values, changed
output, non-UTF-8, and absent expected headings must become Unknown rather than
Absent.

On the inspected machine, the generated plist was readable at
`/Library/LaunchDaemons/org.nixos.nix-gc.plist`; a deployed machine may deny
access or have a broken symlink. File absence, filesystem failure, and parse
failure must remain distinct. Raw plist, stdout, stderr, OS errors, and arbitrary
shell text must not enter the report.

## systemd observation seams

systemd `262~devel` exposes normalized, computer-readable unit properties
through `systemctl show`; `systemctl status` is human-oriented and may
implicitly load a unit
([version](https://github.com/systemd/systemd/blob/07a9d1f929f7ae2c4d4fbbdb0d307d993e83be8e/meson.version),
[systemctl](https://github.com/systemd/systemd/blob/07a9d1f929f7ae2c4d4fbbdb0d307d993e83be8e/man/systemctl.xml)).

| Claim | Read-only property seam |
| --- | --- |
| Configuration | `LoadState`, `FragmentPath`, `DropInPaths`, `UnitFileState`, timer `Unit` |
| Runtime/Activity | Timer and service `ActiveState`, `SubState`; service `MainPID` |
| Schedule | `TimersCalendar`, monotonic timers, next elapse, accuracy, random delay, persistence, wake policy |
| Command | Service `ExecStart` path and argv |
| LastResult | Service `Result`, `ExecMainCode`, `ExecMainStatus`; timer last-trigger timestamp |
| Runs | No lifetime counter; retained journal invocations are retention- and privilege-bounded |
These properties and their typed meanings are part of systemd's D-Bus contract
([D-Bus interfaces](https://github.com/systemd/systemd/blob/07a9d1f929f7ae2c4d4fbbdb0d307d993e83be8e/man/org.freedesktop.systemd1.xml)).
Multiple `OnCalendar` expressions and monotonic timers may coexist; accuracy,
random delay, persistence, and wake policy affect execution semantics
([timer semantics](https://github.com/systemd/systemd/blob/07a9d1f929f7ae2c4d4fbbdb0d307d993e83be8e/man/systemd.timer.xml)).
Calendar expressions include lists, ranges, repetition, and time zones, so the
adapter must preserve the systemd-specific form
([calendar syntax](https://github.com/systemd/systemd/blob/07a9d1f929f7ae2c4d4fbbdb0d307d993e83be8e/man/systemd.time.xml)).
The system manager and calling user's manager are separate scopes. Querying a
specific other user's manager requires a reachable user bus; inactive managers,
authorization failures, and missing buses are Unavailable, not proof of
absence. Static all-user discovery also needs each user's XDG unit paths and
permissions
([manager options](https://github.com/systemd/systemd/blob/07a9d1f929f7ae2c4d4fbbdb0d307d993e83be8e/man/user-system-options.xml),
[unit load paths](https://github.com/systemd/systemd/blob/07a9d1f929f7ae2c4d4fbbdb0d307d993e83be8e/man/systemd.unit.xml)).
`systemctl --version` is the local version probe. A complete readable search
ending in `not-found` supports Absent; bus, permission, or unknown-property
failures support Unavailable. Shell `ExecStart` wrappers remain unattributed.

## Cronie and anacron observation seams

Cronie `1.7.2`'s cron daemon searches `/etc/crontab`, `/etc/cron.d`, and
`/var/spool/cron`; the bundled anacron reads `/etc/anacrontab`.
`crontab -l` lists the calling user's table and `-u` selects another user
([version](https://github.com/cronie-crond/cronie/blob/5f9f16b5663becefdd0dd70df31c0ef5ac36f943/configure.ac),
[daemon](https://github.com/cronie-crond/cronie/blob/5f9f16b5663becefdd0dd70df31c0ef5ac36f943/man/cron.8),
[client](https://github.com/cronie-crond/cronie/blob/5f9f16b5663becefdd0dd70df31c0ef5ac36f943/man/crontab.1)).
Other-user and spool access is privilege-dependent, so an unreadable scope is
Partial/Unavailable rather than Absent.
The five-field grammar, `CRON_TZ`, random delay, and shell command belong in a
Cronie-specific schedule/command parser
([crontab format](https://github.com/cronie-crond/cronie/blob/5f9f16b5663becefdd0dd70df31c0ef5ac36f943/man/crontab.5)).
`cronnext` can calculate next executions, but its command filter is substring
matching and cannot authenticate Nix GC
([cronnext](https://github.com/cronie-crond/cronie/blob/5f9f16b5663becefdd0dd70df31c0ef5ac36f943/man/cronnext.1)).
Cronie has no documented per-job activity API, lifetime run counter, or last
result property; daemon state from the host init system does not establish job
history. Use `crond -V` or `crontab -V` as the version probe.

Anacron parses period, delay, job identifier, and shell command from
`/etc/anacrontab`; after a command exits it stores only the execution date in
`/var/spool/anacron`
([anacrontab](https://github.com/cronie-crond/cronie/blob/5f9f16b5663becefdd0dd70df31c0ef5ac36f943/man/anacrontab.5),
[anacron](https://github.com/cronie-crond/cronie/blob/5f9f16b5663becefdd0dd70df31c0ef5ac36f943/man/anacron.8)).
It exits after due work finishes, so process absence is idle, not disabled.
Timestamp files support a last-run date, not a count or exit result. Alternate
`-t` tables and `-S` spools make arbitrary user instances undiscoverable
without heuristics. Use `anacron -V`; malformed or inaccessible tables and
timestamps are Unavailable.

## fcron observation seams

fcron `3.4.1` supports elapsed-uptime, calendar, and periodic schedules; source
tables are managed by `fcrontab`, while the daemon retains additional compiled
state
([version](https://github.com/yo8192/fcron/blob/a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130/configure.in),
[schedule format](https://github.com/yo8192/fcron/blob/a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130/doc/en/fcrontab.5.sgml),
[table client](https://github.com/yo8192/fcron/blob/a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130/doc/en/fcrontab.1.sgml)).
The read-only `fcrondyn` commands `ls`, `ls_exeq`, queue listings, and `detail`
expose owner, PID, queue state, next schedule, and command. Root may list all
users; ordinary users remain subject to allow/deny and PAM policy
([runtime client](https://github.com/yo8192/fcron/blob/a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130/doc/en/fcrondyn.1.sgml)).
The same interface also has mutating commands, so the adapter must execute only
fixed read-only forms.
`fcron.conf` selects the spool, PID file, FIFO, and permits multiple instances
with different configurations
([configuration](https://github.com/yo8192/fcron/blob/a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130/doc/en/fcron.conf.5.sgml)).
Therefore the selected instance can be scanned, but arbitrary alternate
instances cannot be discovered without heuristics. Connection, permission, or
configuration mismatch is Unavailable, not Absent. The documented query fields
contain no lifetime run count or last exit result. Use `fcron -V`,
`fcrontab -V`, or `fcrondyn -V`; shell command strings remain unattributed.

## Cross-provider normalization boundary

- Execute only fixed paths and fixed read-only arguments; never run a scheduled command.
- Parse exact typed fields, validate UTF-8, ranges, enums, and full revisions,
  then discard stdout, stderr, and OS error text.
- Report Absent only after every authoritative location in the requested scope
  was successfully enumerated; otherwise report Partial or Unavailable.
- Preserve provider-specific schedules. Any common cadence is a derived display
  value.
- No Linux provider was available; Linux findings are source-specification evidence requiring integration fixtures.

## Findings carried into later decisions

- External adapters should supply normalized Observations only. Authority and
  Inference rules remain catalog-controlled.
- Officiality is claim-scoped: a custom launchd/systemd job can have official
  Nix command and scheduler semantics without an official automation mapping.
- OS-specific schedule values must be preserved. A common cadence is a derived
  display value, not the evidence boundary.
- Revision-unavailable, artifact-absent, permission-denied, and malformed output
  are different states.
- Runtime counters and result fields require provider-specific support; absence
  of a durable counter must remain Unknown rather than an invented zero.
