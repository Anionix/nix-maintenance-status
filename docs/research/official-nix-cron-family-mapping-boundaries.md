# Official Nix GC mapping boundaries for the cron family

Status: source-verified on 2026-07-18. This is a research asset for issue #79;
it does not add an adapter or change the catalog.

## Verdict

The official Nix operation is `nix-collect-garbage`. The pinned NixOS module
maps `nix.gc.automatic` to a generated systemd service and timer; it does not
map the option to Cronie, anacron, or fcron. A cron-family observation can
therefore resolve `SchedulerSemantics` only. It must leave
`AutomationMapping` as `NotClaimed` (and never infer a mapping from a command,
package name, or executable name).

The only package/module identities verified below are the exact source pins.
They are not interchangeable: NixOS `services.cron` is ISC cron, `pkgs.cronie`
is a separate package, and `services.fcron` has its own module ([`cron.nix`](https://github.com/NixOS/nixpkgs/blob/e8d924d50a462f89166e31a27bdcbbade35fd8e6/nixos/modules/services/scheduling/cron.nix#L23-L32), [`cronie/package.nix`](https://github.com/NixOS/nixpkgs/blob/e8d924d50a462f89166e31a27bdcbbade35fd8e6/pkgs/by-name/cr/cronie/package.nix#L9-L18), and [`fcron.nix`](https://github.com/NixOS/nixpkgs/blob/e8d924d50a462f89166e31a27bdcbbade35fd8e6/nixos/modules/services/scheduling/fcron.nix#L42-L48)). The Cronie catalog contract pin is a post-1.7.2 commit while the Nixpkgs package builds the 1.7.2 tag ([post-tag contract](https://github.com/cronie-crond/cronie/blob/5f9f16b5663becefdd0dd70df31c0ef5ac36f943/man/crontab.5), [tag package source](https://github.com/cronie-crond/cronie/tree/71894fee3c74f3787e77f21a24fbbe0dffb59e7f)); that combination cannot prove an exact package-backed contract.

## Primary pins and package identity

| Authority or provider | Exact revision and fixed evidence | Implementation consequence |
| --- | --- | --- |
| Nix GC operation | [`NixOS/nix@035f34f13f969cf72ca4ea60369d907972402956`, `nix-collect-garbage.cc`](https://github.com/NixOS/nix/blob/035f34f13f969cf72ca4ea60369d907972402956/src/nix/nix-collect-garbage/nix-collect-garbage.cc#L60-L112) and [`store-gc.cc`](https://github.com/NixOS/nix/blob/035f34f13f969cf72ca4ea60369d907972402956/src/nix/store-gc.cc#L37-L49) | `GcOperationSemantics` may resolve only for this pinned Nix operation; observing a scheduler command is not proof of GC semantics. |
| NixOS GC mapping | [`nix-gc.nix` at Nixpkgs `e8d924d50a462f89166e31a27bdcbbade35fd8e6`](https://github.com/NixOS/nixpkgs/blob/e8d924d50a462f89166e31a27bdcbbade35fd8e6/nixos/modules/services/misc/nix-gc.nix#L78-L100) | `nix.gc.automatic` creates `systemd.services.nix-gc` running `nix-collect-garbage`, plus `systemd.timers.nix-gc` with `RandomizedDelaySec` and `Persistent`; this is the only official mapping established here. |
| NixOS `services.cron` | [`cron.nix` at the same Nixpkgs revision](https://github.com/NixOS/nixpkgs/blob/e8d924d50a462f89166e31a27bdcbbade35fd8e6/nixos/modules/services/scheduling/cron.nix#L23-L32), [`isc-cron/package.nix`](https://github.com/NixOS/nixpkgs/blob/e8d924d50a462f89166e31a27bdcbbade35fd8e6/pkgs/by-name/is/isc-cron/package.nix#L11-L18), and [`all-packages.nix#L1869`](https://github.com/NixOS/nixpkgs/blob/e8d924d50a462f89166e31a27bdcbbade35fd8e6/pkgs/top-level/all-packages.nix#L1869) | The module calls `pkgs.cron`, which aliases ISC cron 4.1; it is not Cronie. |
| Cronie | [`cronie-1.7.2` tag commit `71894fee3c74f3787e77f21a24fbbe0dffb59e7f`](https://github.com/cronie-crond/cronie/tree/71894fee3c74f3787e77f21a24fbbe0dffb59e7f), [`cronie` package expression](https://github.com/NixOS/nixpkgs/blob/e8d924d50a462f89166e31a27bdcbbade35fd8e6/pkgs/by-name/cr/cronie/package.nix#L9-L25), and [`cronie` contract pin `5f9f16b5663becefdd0dd70df31c0ef5ac36f943`](https://github.com/cronie-crond/cronie/blob/5f9f16b5663becefdd0dd70df31c0ef5ac36f943/man/crontab.5) | Nixpkgs builds the tag plus GCC-15 patch `09c630c654b2aeff06a90a412cce0a60ab4955a`; the post-tag contract pin and package source must be separate identities until reconciled. |
| Anacron | [`anacron.8` and `anacrontab.5` at Cronie `5f9f16b5663becefdd0dd70df31c0ef5ac36f943`](https://github.com/cronie-crond/cronie/blob/5f9f16b5663becefdd0dd70df31c0ef5ac36f943/man/anacron.8) | Anacron is a Cronie-tree tool with a separate table/runtime contract; no NixOS `services.anacron` module is present in the fixed [`scheduling` module tree](https://github.com/NixOS/nixpkgs/tree/e8d924d50a462f89166e31a27bdcbbade35fd8e6/nixos/modules/services/scheduling). |
| fcron 3.4.0 | [`ver3_4_0` commit `8198d4b90690fb0f53cca931b6e9bb6d4b9e6f83`](https://github.com/yo8192/fcron/tree/8198d4b90690fb0f53cca931b6e9bb6d4b9e6f83), [`fcron` package expression](https://github.com/NixOS/nixpkgs/blob/e8d924d50a462f89166e31a27bdcbbade35fd8e6/pkgs/by-name/fc/fcron/package.nix#L17-L29), and [`relative-fcronsighup.patch` blob `c0bbfc1ee3ef4b40acddcd3c9b60ccd413920a88`](https://github.com/NixOS/nixpkgs/blob/e8d924d50a462f89166e31a27bdcbbade35fd8e6/pkgs/by-name/fc/fcron/relative-fcronsighup.patch) | Nixpkgs builds 3.4.0 from the upstream tarball hash and applies the fixed local patch. Preserve this package identity separately from upstream contract identity. |
| fcron 3.4.1 | [`ver3_4_1` commit `a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130`](https://github.com/yo8192/fcron/tree/a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130) and [`fcrontab.5.sgml`](https://github.com/yo8192/fcron/blob/a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130/doc/en/fcrontab.5.sgml) | Keep 3.4.1 as its own `SchedulerSemantics` contract; the pinned Nixpkgs expression above is 3.4.0, not 3.4.1. |

## Read-only evidence contract

### Cronie

The Cronie daemon contract names `/etc/crontab`, `/etc/cron.d/`, and
`/var/spool/cron` as the system and per-user roots and describes mtime/inotify
reload behavior ([`cron.8`](https://github.com/cronie-crond/cronie/blob/5f9f16b5663becefdd0dd70df31c0ef5ac36f943/man/cron.8#L91-L107)). The table grammar includes `CRON_TZ` and bounded
`RANDOM_DELAY` ([`crontab.5`](https://github.com/cronie-crond/cronie/blob/5f9f16b5663becefdd0dd70df31c0ef5ac36f943/man/crontab.5#L119-L160)). A reader may
bounded-read those roots, parse the provider grammar, and preserve timezone
and randomization bounds; it must not fabricate a sampled delay or daemon
status.

Cronie itself opens tables read-only and uses `fstat`; its database loader also
performs passwd lookups ([`database.c`](https://github.com/cronie-crond/cronie/blob/5f9f16b5663becefdd0dd70df31c0ef5ac36f943/src/database.c#L69-L85) and
[`database.c#L219-L239`](https://github.com/cronie-crond/cronie/blob/5f9f16b5663becefdd0dd70df31c0ef5ac36f943/src/database.c#L219-L239)). The adapter must use a bounded local
`/etc/passwd` snapshot for subject allocation: no `crontab -u`, NSS/network,
user switching, or command execution. Table presence is configuration evidence
only; it cannot establish Runtime, Activity, or LastResult.

### Anacron

The fixed anacron contract uses `/etc/anacrontab`, rows of period/delay/unique
identifier/command, and timestamp files under `/var/spool/anacron`
([`anacron.8`](https://github.com/cronie-crond/cronie/blob/5f9f16b5663becefdd0dd70df31c0ef5ac36f943/man/anacron.8#L15-L45) and
[`anacrontab.5`](https://github.com/cronie-crond/cronie/blob/5f9f16b5663becefdd0dd70df31c0ef5ac36f943/man/anacrontab.5#L1-L66)). The parser opens the table with
`fopen(..., "r")` and accepts numeric/named periods, `START_HOURS_RANGE`, and
`RANDOM_DELAY` ([`readtab.c`](https://github.com/cronie-crond/cronie/blob/5f9f16b5663becefdd0dd70df31c0ef5ac36f943/anacron/readtab.c#L292-L399)). A reader may parse the table and existing
timestamp bytes only.

Anacron's normal runtime opens timestamp files with `O_RDWR|O_CREAT`, takes a
write lock, and writes the completion date ([`lock.c`](https://github.com/cronie-crond/cronie/blob/5f9f16b5663becefdd0dd70df31c0ef5ac36f943/anacron/lock.c#L41-L70) and
[`lock.c#L191-L216`](https://github.com/cronie-crond/cronie/blob/5f9f16b5663becefdd0dd70df31c0ef5ac36f943/anacron/lock.c#L191-L216)). Therefore `-u`, `-f`,
execution, lock probes, create/chown/chmod, and timestamp updates are forbidden.
An existing timestamp can support a last-run-date observation; active state,
Runtime, and LastResult remain `Unknown`/`Unavailable`.

### fcron

The fcron table contract has environment/option lines and three native schedule
families: elapsed fcron uptime, absolute five-field time/date, and periodic
entries ([`fcrontab.5.sgml`](https://github.com/yo8192/fcron/blob/a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130/doc/en/fcrontab.5.sgml#L27-L58),
[`#L85-L176`](https://github.com/yo8192/fcron/blob/a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130/doc/en/fcrontab.5.sgml#L85-L176), and
[`#L880-L885`](https://github.com/yo8192/fcron/blob/a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130/doc/en/fcrontab.5.sgml#L880-L885)). Its config contract supplies the
spool, pid, and FIFO paths ([`fcron.conf.5.sgml`](https://github.com/yo8192/fcron/blob/a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130/doc/en/fcron.conf.5.sgml#L47-L94)); NixOS writes
`fcrontabs = /var/spool/fcron` and starts `fcron` from its module
([`fcron.nix`](https://github.com/NixOS/nixpkgs/blob/e8d924d50a462f89166e31a27bdcbbade35fd8e6/nixos/modules/services/scheduling/fcron.nix#L102-L176)).

The fcron CLI installs/updates generated tables and the daemon has a dynamic
client; those are commands, not safe probes ([`fcrontab.1.sgml`](https://github.com/yo8192/fcron/blob/a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130/doc/en/fcrontab.1.sgml#L52-L68) and
[`fcrondyn.1.sgml`](https://github.com/yo8192/fcron/blob/a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130/doc/en/fcrondyn.1.sgml#L22-L50)). Read the configured source table and
bounded metadata directly; do not invoke `fcrontab`, `fcrondyn`, or `fcron`.
Without a daemon/status API that satisfies the read-only boundary, Runtime,
Activity, and LastResult are `Unknown`/`Unavailable`.

### Probe matrix

| Provider | Safe local revision probe | Forbidden action | Maximum claim from the probe |
| --- | --- | --- | --- |
| Cronie | Bounded `read`/`stat` of `/etc/crontab`, `/etc/cron.d/*`, `/var/spool/cron/*`, plus a local `/etc/passwd` snapshot; roots are fixed by [`cron.8`](https://github.com/cronie-crond/cronie/blob/5f9f16b5663becefdd0dd70df31c0ef5ac36f943/man/cron.8#L91-L107) and read-only opening is shown in [`database.c`](https://github.com/cronie-crond/cronie/blob/5f9f16b5663becefdd0dd70df31c0ef5ac36f943/src/database.c#L69-L85). | `crontab -u/-l`, NSS/network, user switching, process or log queries. | Configuration and `SchedulerSemantics` only; no daemon/runtime/activity result. |
| Anacron | Bounded `read`/`stat` of `/etc/anacrontab` and existing `/var/spool/anacron/<identifier>` bytes ([`anacron.8`](https://github.com/cronie-crond/cronie/blob/5f9f16b5663becefdd0dd70df31c0ef5ac36f943/man/anacron.8#L15-L45)). | `-u`, `-f`, execution, lock acquisition, create/chown/chmod, or timestamp update ([`lock.c`](https://github.com/cronie-crond/cronie/blob/5f9f16b5663becefdd0dd70df31c0ef5ac36f943/anacron/lock.c#L41-L70)). | Schedule plus an existing last-run date; active/runtime/result are unavailable. |
| fcron | Read the configured `fcron.conf` and source table under its configured spool; NixOS writes `/var/spool/fcron` ([`fcron.conf.5.sgml`](https://github.com/yo8192/fcron/blob/a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130/doc/en/fcron.conf.5.sgml#L47-L94), [`fcron.nix`](https://github.com/NixOS/nixpkgs/blob/e8d924d50a462f89166e31a27bdcbbade35fd8e6/nixos/modules/services/scheduling/fcron.nix#L102-L118)). | `fcrontab`, `fcrondyn`, `fcron`, FIFO writes, or generated-table updates ([`fcrontab.1.sgml`](https://github.com/yo8192/fcron/blob/a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130/doc/en/fcrontab.1.sgml#L52-L68)). | Provider schedule only; no runtime/activity/result claim. |

Local metadata cannot establish a source commit or package patch identity.
Only an exact catalog fingerprint may resolve `SchedulerSemantics`; otherwise
the adapter retains observations while returning `Unresolved` authority.

## Role outcomes and #32 split

| Provider | `GcOperationSemantics` | `AutomationMapping` | `SchedulerSemantics` |
| --- | --- | --- | --- |
| Cronie | `NotClaimed` unless a command is independently matched to the pinned Nix operation | `NotClaimed`; no NixOS Cronie mapping | `Resolved` only for an exact Cronie contract/package identity; current post-tag-vs-tag mismatch is `Unresolved` |
| Anacron | `NotClaimed` | `NotClaimed` and system-only roots; no NixOS anacron module | `Resolved` for the exact anacron contract; active/runtime leaves remain unavailable |
| fcron 3.4.0 / 3.4.1 | `NotClaimed` | `NotClaimed`; NixOS `services.fcron` is scheduler wiring, not `nix.gc` mapping | Separate exact contracts; 3.4.0 package identity does not resolve 3.4.1 |

Issue #32 must split implementation into (1) catalog/package identity and the
explicit no-mapping decision, (2) Cronie direct-file schedule parsing, (3)
Anacron table/timestamp parsing with catch-up and random-delay bounds, and (4)
fcron 3.4.0 and 3.4.1 as separate provider contracts. Any status integration
would be a separate, non-read-only boundary. All probes remain bounded,
read-only, local, no NSS/network, no commands, no locks, no mutation, and no
telemetry.

## Reproducibility proof

This branch starts at `origin/main` commit `674e2bf554207f316fc8645d3f482f7816b46ff1`.
The research session changes exactly this Markdown asset; no Rust, README, ADR,
flake, or lockfile file is part of the change.
