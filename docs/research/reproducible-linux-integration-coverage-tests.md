# Reproducible Linux integration and all-user coverage tests

Status: research snapshot, 2026-07-16

This note answers which environments can verify Linux scheduler adapters for
the experimental 0.2 design without changing a GitHub-hosted runner or granting
the diagnostic elevated privileges. It records test evidence and recommended
coverage, not the final Rust API or CLI exit policy.

## Result

Use three evidence layers:

1. deterministic parser fixtures on every Rust host;
2. two `x86_64-linux` `pkgs.testers.runNixOSTest` derivations on
   `ubuntu-latest`;
3. native Linux and existing macOS smoke tests only for host-boundary behavior.

The Linux VM tests are the authoritative integration layer. They boot complete
NixOS systems in QEMU, can create system and user managers, and keep all root
setup inside disposable guests. Parser fixtures cannot establish operating
system behavior. Containers share the host kernel and require extra Nix daemon
features, so they add no required proof for this 0.2 matrix. A native hosted
runner smoke test can establish safe Linux dispatch and lack of elevation, but
must not install schedulers, edit system units, enumerate real users, or use
`sudo`; controlled no-job evidence belongs in a VM.

## Fixed sources and local verification

| Source | Fixed point |
| --- | --- |
| Repository baseline | [`08a68869fc76d02b0b6d6b6a7a998fa0ccd0344a`](https://github.com/Anionix/nix-maintenance-status/tree/08a68869fc76d02b0b6d6b6a7a998fa0ccd0344a) |
| Locked Nixpkgs | [`6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee`](https://github.com/NixOS/nixpkgs/tree/6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee) |
| systemd semantics | [`07a9d1f929f7ae2c4d4fbbdb0d307d993e83be8e`](https://github.com/systemd/systemd/tree/07a9d1f929f7ae2c4d4fbbdb0d307d993e83be8e) |
| Cronie/anacron semantics | [`5f9f16b5663becefdd0dd70df31c0ef5ac36f943`](https://github.com/cronie-crond/cronie/tree/5f9f16b5663becefdd0dd70df31c0ef5ac36f943) |
| fcron semantics | [`a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130`](https://github.com/yo8192/fcron/tree/a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130) |
| GitHub runner contract | [GitHub-hosted runners, Free/Pro/Team, accessed 2026-07-16](https://docs.github.com/en/actions/reference/runners/github-hosted-runners) |

Local evaluation of the locked Nixpkgs revision found
`pkgs.testers.runNixOSTest` callable and resolved the Linux packages to
systemd `261`, Cronie `1.7.2`, and fcron `3.4.0`. Their package definitions are
fixed at [systemd](https://github.com/NixOS/nixpkgs/blob/6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee/pkgs/os-specific/linux/systemd/default.nix),
[Cronie](https://github.com/NixOS/nixpkgs/blob/6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee/pkgs/by-name/cr/cronie/package.nix),
and [fcron](https://github.com/NixOS/nixpkgs/blob/6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee/pkgs/by-name/fc/fcron/package.nix).

The local host was macOS 27.0 build `26A5378j`, `aarch64-darwin`, with Nix
`2.34.7+1`. Linux VMs and Linux scheduler probes were **not** executed locally.
The NixOS manual states that macOS needs a Linux builder to run these tests
([requirements](https://github.com/NixOS/nixpkgs/blob/6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee/nixos/doc/manual/development/running-nixos-tests.section.md#L22-L31)).
All Linux execution proposals below are therefore source-specified and require
future CI verification.

## Current repository boundary

The current flake enumerates only `aarch64-darwin` and `x86_64-darwin`, and its
package metadata is Darwin-only
([flake](https://github.com/Anionix/nix-maintenance-status/blob/08a68869fc76d02b0b6d6b6a7a998fa0ccd0344a/flake.nix)).
The Linux job runs Rust formatting, Clippy, and Cargo tests; only the macOS job
installs Nix and runs `nix flake check` plus a no-job smoke test
([workflow](https://github.com/Anionix/nix-maintenance-status/blob/08a68869fc76d02b0b6d6b6a7a998fa0ccd0344a/.github/workflows/ci.yml)).
Adding Linux flake outputs and VM checks is future implementation work, not part
of this research change.

## What each environment can prove

| Environment | Authoritative proof | Cannot prove |
| --- | --- | --- |
| Parser fixtures | Total normalization, exact malformed-input handling, raw-output disposal, deterministic `Present`/`Absent`/`Unavailable` transitions | Installed paths, manager behavior, kernel credentials, D-Bus permissions, real user-manager lifecycle |
| NixOS QEMU VM | NixOS module output, systemd system/user managers, real file modes and UIDs, packaged Cronie/anacron/fcron, process exit and permission behavior | Non-NixOS distributions, architectures not built, host-specific policy outside the VM |
| NixOS `systemd-nspawn` container | NixOS userspace with systemd on a shared Linux kernel; cheaper multi-node experiments | Separate-kernel behavior, setuid binaries, systemd namespacing options, ordinary hosted-runner compatibility |
| Native `ubuntu-latest` smoke | CLI starts safely on the supported OS and does not elevate | Controlled scheduler versions, controlled empty inventory, exhaustive user coverage, safe mutation of system configuration |
| Existing `macos-latest` smoke | Existing launchd/nix-darwin no-job boundary | Any Linux scheduler or Linux coverage semantics |

NixOS defines test `nodes` as QEMU VMs and `containers` as
`systemd-nspawn` containers, and permits external projects to call
`pkgs.testers.runNixOSTest`
([test structure](https://github.com/NixOS/nixpkgs/blob/6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee/nixos/doc/manual/development/writing-nixos-tests.section.md#L3-L49),
[external invocation](https://github.com/NixOS/nixpkgs/blob/6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee/nixos/doc/manual/development/writing-nixos-tests.section.md#L95-L111)).
The documented VM/container comparison says containers share the host kernel,
while VMs permit setuid binaries and systemd namespacing features
([comparison](https://github.com/NixOS/nixpkgs/blob/6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee/nixos/doc/manual/development/writing-nixos-tests.section.md#L128-L151)).

Linux VM tests normally require the `kvm` system feature, but the test option
explicitly allows `requiredFeatures.kvm = false` for emulated execution
([test option](https://github.com/NixOS/nixpkgs/blob/6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee/nixos/lib/testing/run.nix#L33-L64)).
The CI check must select emulation rather than inspect, enable, or change
`/dev/kvm` on the hosted runner. This avoids treating undocumented runner
acceleration as a contract.

Containers require `auto-allocate-uids`, `uid-range`, and experimental `cgroups`
Nix daemon settings
([container requirements](https://github.com/NixOS/nixpkgs/blob/6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee/nixos/doc/manual/development/running-nixos-tests.section.md#L32-L52)).
Changing those settings on `ubuntu-latest` would mutate the host Nix daemon.
Containers are therefore optional local optimization, not a required CI gate.

## Provider availability at the locked revision

| Provider | Locked availability | Reproducible configuration |
| --- | --- | --- |
| systemd | NixOS system manager and package `261` | NixOS `systemd.services`, `systemd.timers`, and `systemd.user.*` modules |
| Cronie | `pkgs.cronie` `1.7.2` | Explicit VM package and test-only service/configuration; no dedicated NixOS Cronie module was found |
| anacron | Built from the Cronie source; no separate `pkgs.anacron` attribute | Cronie package plus an explicit `/etc/anacrontab` and isolated spool |
| fcron | `pkgs.fcron` `3.4.0` and `services.fcron` | NixOS module provisions config, spool, wrappers, user/group, and `fcron.service` |

The existing `services.cron` module invokes `pkgs.cron`, whose locked package is
ISC cron `4.1`, not Cronie
([module](https://github.com/NixOS/nixpkgs/blob/6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee/nixos/modules/services/scheduling/cron.nix#L93-L140),
[ISC package](https://github.com/NixOS/nixpkgs/blob/6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee/pkgs/by-name/is/isc-cron/package.nix)).
It must not be used as a Cronie substitute in this matrix.

Cronie's build includes its anacron module
([upstream build](https://github.com/cronie-crond/cronie/blob/5f9f16b5663becefdd0dd70df31c0ef5ac36f943/Makefile.am#L13-L35)).
The Nixpkgs Cronie package does not disable it
([package flags](https://github.com/NixOS/nixpkgs/blob/6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee/pkgs/by-name/cr/cronie/package.nix#L9-L38)).
The fcron module defines its spool paths, access files, wrappers, system user,
and service, making it the strongest packaged fcron fixture
([fcron module](https://github.com/NixOS/nixpkgs/blob/6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee/nixos/modules/services/scheduling/fcron.nix#L88-L176)).

## Recommended minimum integration matrix

| Check | Host | Contents | Required result |
| --- | --- | --- | --- |
| `rust-fixtures` | `ubuntu-latest` Cargo job | Synthetic systemd properties, crontabs, anacron timestamps, fcron query output; malformed and command-failure cases | All parser state transitions; no raw stdout/stderr in reports or snapshots |
| `nixos-systemd-coverage` | `ubuntu-latest`, `runNixOSTest`, emulated `x86_64-linux` VM | system timer/service, active lingering user, inactive user, unreadable subject evidence, empty inventory | system/current/all-users and `Complete`/`Partial`/`Unavailable` evidence |
| `nixos-scheduler-catalog` | same, separate `runNixOSTest` derivation | Cronie+anacron node and fcron node, system/user jobs, wrappers, malformed tables, denied reads | provider installation, authoritative roots, permission and no-job normalization |
| `linux-native-smoke` | unmodified `ubuntu-latest` | built CLI only; no scheduler installation or host enumeration beyond default scope | read-only startup, supported-platform dispatch, no `sudo`, no GC execution |
| `macos-nix-integration` | current `macos-latest` job | existing Cargo, flake, and launchd no-job smoke | preserve the existing macOS boundary unchanged |

Two Linux VM derivations are preferred to one large test. They independently
cache and report failures, while each may contain multiple nodes. No timing is
assumed. The public `ubuntu-latest` contract currently provides a fresh x64 VM
with 4 CPUs, 16 GB RAM, and 14 GB SSD; `-latest` denotes GitHub's latest stable
image, not necessarily the vendor's newest OS
([runner table](https://docs.github.com/en/actions/reference/runners/github-hosted-runners#standard-github-hosted-runners-for-public-repositories),
accessed 2026-07-16).

GitHub documents passwordless `sudo` on hosted Linux VMs
([administrative privileges](https://docs.github.com/en/actions/reference/runners/github-hosted-runners#administrative-privileges),
accessed 2026-07-16). The availability of that privilege is not permission to
use it: all privileged fixture construction belongs inside the NixOS VM.

## VM topology and subjects

The `nixos-systemd-coverage` VM declares:

- `alice`, with `linger = true`, an active user manager, and a GC-like user
  timer/service;
- `bob`, with `linger = false`, no login session, and no active user manager;
- one system timer/service, plus a separate complete no-job generation;
- one evidence root readable by the diagnostic and one root denied to its
  unprivileged test identity.

Nixpkgs's own test declares lingering and non-lingering users, waits for
Alice's user slice, and verifies Bob's slice is absent
([fixed linger test](https://github.com/NixOS/nixpkgs/blob/6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee/nixos/tests/systemd-user-linger.nix#L1-L38)).
The test driver also supports a user argument for systemd unit operations
([user-unit testing](https://github.com/NixOS/nixpkgs/blob/6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee/nixos/doc/manual/development/writing-nixos-tests.section.md#L246-L258)).
Thus active and inactive managers are reproducible without logging into or
modifying the GitHub runner.

The `nixos-scheduler-catalog` derivation uses two nodes:

- `cronie`: installs `pkgs.cronie`, runs only test-owned Cronie configuration,
  supplies system and per-user crontabs, `/etc/anacrontab`, and an isolated
  anacron spool;
- `fcron`: enables `services.fcron`, supplies system and per-user tables, and
  exercises only fixed read-only `fcrondyn`/`fcrontab` queries.

Scheduled commands must be inert fixtures such as `/run/current-system/sw/bin/true`.
The test never runs Nix GC. Wrapper strings are observed as wrappers and are not
promoted to official Nix automation.

## Scenario and expected evidence table

| Scenario | Authoritative layer | Expected normalized evidence |
| --- | --- | --- |
| systemd system timer present | systemd VM | provider present; system subject; configuration/runtime/schedule readable |
| current user manager active | systemd VM, Alice | user automation present; user manager reachable |
| user manager inactive | systemd VM, Bob | subject enumerated; runtime unavailable, never global absence |
| all users readable | both VM checks | every declared subject/root inspected; `Complete` candidate |
| one user/root denied | VM executed as unprivileged diagnostic identity | visible automations retained; denied component yields `Partial` candidate |
| every required seam denied or missing command | VM plus process fixture | inventory not declared empty; `Unavailable` candidate |
| provider installed, no jobs | VM | known empty provider inventory, not provider failure |
| controlled complete no-job scope | systemd and scheduler VMs | known empty inventory; no host mutation |
| malformed systemd property or table | parser fixture, then selected VM file case | malformed component is unavailable; raw bytes discarded |
| duplicate jobs or wrapper command | fixture | distinct observations retained; attribution left to later decision |
| anacron timestamp readable | Cronie VM | last-run date observation only |
| fcron daemon reachable but another user denied | fcron VM | current/system observations plus partial all-user coverage |
| diagnostic runtime network disabled | both VM checks | same normalized result; no AF_INET/AF_INET6 dependency |
| report contains secrets/raw probe text | all layers | hard failure |

Cronie permits user-specific table listing through `crontab`, but other-user
access is privilege-dependent
([Cronie client](https://github.com/cronie-crond/cronie/blob/5f9f16b5663becefdd0dd70df31c0ef5ac36f943/man/crontab.1)).
Anacron uses a table and spool timestamps rather than a persistent daemon API
([anacron manual](https://github.com/cronie-crond/cronie/blob/5f9f16b5663becefdd0dd70df31c0ef5ac36f943/man/anacron.8),
[table format](https://github.com/cronie-crond/cronie/blob/5f9f16b5663becefdd0dd70df31c0ef5ac36f943/man/anacrontab.5)).
fcron exposes user-scoped read operations subject to its access policy
([fcrondyn](https://github.com/yo8192/fcron/blob/a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130/doc/en/fcrondyn.1.sgml)).
These upstream boundaries require real permission tests; fixture-only denial
cannot prove kernel credential behavior.

## Coverage and exit assertions

The VM oracle should compute scan completeness separately from inventory
contents:

- `Complete`: every authoritative location and manager required by the selected
  scope was enumerated successfully, including an empty result;
- `Partial`: at least one component was enumerated and at least one required
  component was unavailable;
- `Unavailable`: no required component in the selected scope could be
  enumerated.

These names are Wayfinder candidates, not an already published API. Tests
should record component outcomes first and assert the aggregate only after
[Decide Linux scan scopes, permissions, and Coverage semantics](https://github.com/Anionix/nix-maintenance-status/issues/18)
fixes the formal Coverage rules.

The minimum exit scenarios are:

| Evidence | Exit assertion now |
| --- | --- |
| Complete and known empty | reserve an explicit success test; recommended exit `0` |
| Complete with automations | success, exit `0` |
| Partial with useful inventory | render inventory and coverage; final code deferred to the Coverage and CLI decision tickets |
| Unavailable | render normalized reasons without raw errors; recommended exit `2` |
| unsupported platform | retain current exit `2` until the Linux implementation replaces it |

The unresolved Partial exit code is a product contract, not an external fact.
This research must not silently select it before the Coverage and CLI decision
tickets.

## Read-only, offline, and privacy contract

- CI may download source and substitutes before the diagnostic runs. The
  diagnostic process itself must run with outbound IPv4/IPv6 unavailable;
  local Unix sockets remain allowed for systemd/fcron observation.
- Fixture setup may use root **inside** the disposable VM. The diagnostic runs
  as the declared unprivileged identity and must not elevate, write scheduler
  state, enable linger, reload managers, execute scheduled commands, or run GC.
- Tests use synthetic subjects (`alice`, `bob`) and inert commands. They do not
  inspect hosted-runner users, home directories, crontabs, journals, or secrets.
- Parsers retain only normalized fields. CI logs, snapshots, and failure
  messages must not include raw stdout/stderr, environment contents, table
  bodies, OS error strings, or arbitrary command text.
- Read-only guarantees are checked by hashing/mode-checking test-owned evidence
  before and after the diagnostic and by failing if the report includes planted
  sentinel secrets.

## Limitations and questions carried forward

- Linux execution remains unverified on the local macOS host.
- QEMU emulation avoids relying on hosted KVM, but its eventual resource use
  must be learned from CI; no timing or cache-hit promise is made.
- The locked NixOS cron module is ISC cron, so Cronie requires an explicit
  test-only service. That proves the Cronie adapter, not an official NixOS
  Cronie automation mapping.
- The fcron VM proves the NixOS-packaged instance. Arbitrary alternate
  `fcron.conf` instances remain outside non-heuristic discovery.
- A complete all-users inventory still requires
  [Decide Linux scan scopes, permissions, and Coverage semantics](https://github.com/Anionix/nix-maintenance-status/issues/18)
  to define the finite subject set and privacy rules.
- The exit code for useful `Partial` results remains for that Coverage decision
  and
  [Prototype multi-provider Summary and Explain output](https://github.com/Anionix/nix-maintenance-status/issues/23).

The minimum matrix is therefore parser fixtures, two emulated NixOS VM checks,
one unmodified Linux smoke, and the existing macOS smoke. No container gate,
host `sudo`, self-hosted runner, network service, or privileged mutation of a
GitHub-hosted runner is required.
