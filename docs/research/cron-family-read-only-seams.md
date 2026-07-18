# Cron-family read-only observation seams

Status: primary-source research for [#80](https://github.com/Anionix/nix-maintenance-status/issues/80).

This asset fixes the observation boundary for Cronie, its bundled Anacron, and
fcron. It is a research contract, not an implementation. All source anchors
below are immutable commit or tag permalinks. No scheduler was started or
queried by this research session; platform behaviour marked **unexecuted** is
derived from the cited source only.

## Authority pins

| Provider | Authority source | Pin used in this research |
| --- | --- | --- |
| Cronie | [cronie-crond/cronie](https://github.com/cronie-crond/cronie) | `cronie-1.7.2` → [`71894fee3c74f3787e77f21a24fbbe0dffb59e7f`](https://github.com/cronie-crond/cronie/tree/71894fee3c74f3787e77f21a24fbbe0dffb59e7f) |
| Anacron | The Anacron implementation shipped in the same Cronie source tree | [`71894fee3c74f3787e77f21a24fbbe0dffb59e7f`](https://github.com/cronie-crond/cronie/tree/71894fee3c74f3787e77f21a24fbbe0dffb59e7f), `anacron/` |
| fcron 3.4.0 | [yo8192/fcron](https://github.com/yo8192/fcron) | `ver3_4_0` → [`8198d4b90690fb0f53cca931b6e9bb6d4b9e6f83`](https://github.com/yo8192/fcron/tree/8198d4b90690fb0f53cca931b6e9bb6d4b9e6f83) |
| fcron 3.4.1 | [yo8192/fcron](https://github.com/yo8192/fcron) | `ver3_4_1` → [`a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130`](https://github.com/yo8192/fcron/tree/a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130) |

The pinned Nixpkgs revision used by this repository is
`6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee`. Its official package pins Cronie
1.7.2 and an additional GCC patch, while fcron is 3.4.0 from the upstream
source archive plus `relative-fcronsighup.patch` ([Cronie package](https://github.com/NixOS/nixpkgs/blob/6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee/pkgs/by-name/cr/cronie/package.nix),
[fcron package](https://github.com/NixOS/nixpkgs/blob/6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee/pkgs/by-name/fc/fcron/package.nix),
[fcron patch](https://github.com/NixOS/nixpkgs/blob/6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee/pkgs/by-name/fc/fcron/relative-fcronsighup.patch)).
Consequently, package identity is `(nixpkgs revision, source hash, patch
hash)`, not a bare executable version.

The same Nixpkgs revision has a `services.fcron` module, but its scheduling
module list has no `services.anacron` module; Cronie is packaged separately and
is not selected by `services.cron` ([fcron module](https://github.com/NixOS/nixpkgs/blob/6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee/nixos/modules/services/scheduling/fcron.nix),
[scheduling modules](https://github.com/NixOS/nixpkgs/tree/6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee/nixos/modules/services/scheduling)).
This is a source-tree fact for this pin, not a claim about every Nixpkgs
revision.

## Shared safety contract

* The diagnostic reads regular files and manager metadata only. It never calls
  an install, edit, remove, force, update, run, signal, reload, or scheduler
  control operation. The read-only `-l`/`-T` commands documented by providers
  are useful fixture oracles, but the production adapter should prefer direct
  file reads so that “no scheduler command execution” remains literal.
* A failed `stat`, directory open, file open, encoding conversion, bounded read,
  or generation check is **Unavailable**; it is never **Absent**. A regular
  readable file that is valid but has zero jobs is **PresentEmpty**. A missing
  file or directory entry is **Absent**.
* The parser retains normalized schedule fields, booleans, periods, delays,
  timezone identifiers, and an opaque command classification only. Raw table
  text, paths, filenames, usernames, command strings, control bytes, and OS
  error text do not cross the adapter boundary.
* A scheduler’s existence does not establish that Nix garbage collection is
  configured. `GcCommandSemantics` and `AutomationMapping` require a separate
  exact Nix/NixOS fingerprint; generic Cronie, Anacron, or fcron observations
  are `SchedulerSemantics` only. The pinned NixOS Cronie/fcron modules provide
  generic scheduler configuration rather than a Nix GC mapping ([cron module](https://github.com/NixOS/nixpkgs/blob/6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee/nixos/modules/services/scheduling/cron.nix),
  [fcron module](https://github.com/NixOS/nixpkgs/blob/6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee/nixos/modules/services/scheduling/fcron.nix)).

## Cronie

### Configuration and schedule

Cronie reads `/etc/crontab`, files in `/etc/cron.d`, and user crontabs in
`/var/spool/cron`; the daemon’s source documents these three locations and
the distinct system/user grammar ([`cron.8`](https://github.com/cronie-crond/cronie/blob/71894fee3c74f3787e77f21a24fbbe0dffb59e7f/man/cron.8),
[`crontab.5`](https://github.com/cronie-crond/cronie/blob/71894fee3c74f3787e77f21a24fbbe0dffb59e7f/man/crontab.5)).
System entries have a username field; per-user entries do not. The parser must
reject non-regular files, unsafe modes, wrong owners, and unexpected hard-link
counts when the daemon’s default safety policy is in force ([`database.c`](https://github.com/cronie-crond/cronie/blob/71894fee3c74f3787e77f21a24fbbe0dffb59e7f/src/database.c)).

The schedule grammar includes five time fields, lists, ranges, steps, names,
tilde-selected random values, `CRON_TZ`, `RANDOM_DELAY`, `%` command-input
splitting, and DST-specific matching rules ([`crontab.5`](https://github.com/cronie-crond/cronie/blob/71894fee3c74f3787e77f21a24fbbe0dffb59e7f/man/crontab.5)).
The adapter must preserve those semantics as typed fields; it must not render a
raw command or assume that a random field is a stable next timestamp.

`cronnext` is an official read-only schedule calculator. It can select or
exclude users, include system tables, calculate a bounded time interval, and
print either next times or whole entries ([`cronnext.1`](https://github.com/cronie-crond/cronie/blob/71894fee3c74f3787e77f21a24fbbe0dffb59e7f/man/cronnext.1)).
Its text output is not a stable report protocol, so a future adapter may use it
only inside a version-pinned fixture oracle, not as a production wire format.

### Runtime and limits

The official daemon interface is process/service startup plus signals; the
manual documents no query/status endpoint. It reloads when spool mtimes change,
or through inotify when available, and can run in foreground with `-n`/`-f`
([`cron.8`](https://github.com/cronie-crond/cronie/blob/71894fee3c74f3787e77f21a24fbbe0dffb59e7f/man/cron.8),
[`cron.c`](https://github.com/cronie-crond/cronie/blob/71894fee3c74f3787e77f21a24fbbe0dffb59e7f/src/cron.c)).
Therefore `Runtime`, `Activity`, `Runs`, and `LastResult` are **Unknown** unless
an external, explicitly pinned service-manager adapter supplies those claims.
PID existence, syslog text, and process command lines are not authoritative
provider APIs.

`crond` opens each candidate with `O_RDONLY|O_NONBLOCK`, then applies the
regular-file/mode/owner/link checks before parsing. The diagnostic should use a
descriptor-relative bounded read and compare `(dev, ino, size, mtime, nlink)`
before and after parsing; any change is **Unavailable/changed-generation**
([`database.c`](https://github.com/cronie-crond/cronie/blob/71894fee3c74f3787e77f21a24fbbe0dffb59e7f/src/database.c)).
This is stricter than Cronie’s own mtime cache and closes the TOCTOU seam for a
read-only observer.

`crontab.allow`/`crontab.deny` gate use of the `crontab` client, while PAM may
add access control; the daemon can still execute an existing table after client
access is denied ([`crontab.1`](https://github.com/cronie-crond/cronie/blob/71894fee3c74f3787e77f21a24fbbe0dffb59e7f/man/crontab.1),
[`cron.8`](https://github.com/cronie-crond/cronie/blob/71894fee3c74f3787e77f21a24fbbe0dffb59e7f/man/cron.8)).
Current-user scope can read the caller-owned regular table. System scope can
read `/etc/crontab` and `/etc/cron.d` only when permissions allow. All-user
scope may enumerate directory entries without `crontab -u`, but each unreadable,
orphaned, unsafe, or non-regular entry lowers coverage; it must not be reported
as absent.

## Anacron (Cronie source tree)

### Configuration and schedule

Anacron reads `/etc/anacrontab`; each job has period-days, delay-minutes,
identifier, and command. `START_HOURS_RANGE`, `RANDOM_DELAY`, `MAILTO`, and
line continuation are part of the documented grammar ([`anacron.8`](https://github.com/cronie-crond/cronie/blob/71894fee3c74f3787e77f21a24fbbe0dffb59e7f/man/anacron.8),
[`anacrontab.5`](https://github.com/cronie-crond/cronie/blob/71894fee3c74f3787e77f21a24fbbe0dffb59e7f/man/anacrontab.5)).
Named periods include daily, weekly, monthly, yearly, and annually; periods
below one day are not represented by this scheduler ([`anacron.8`](https://github.com/cronie-crond/cronie/blob/71894fee3c74f3787e77f21a24fbbe0dffb59e7f/man/anacron.8)).

`anacron -T` validates an anacrontab and exits without entering the execution
path; `-u` updates timestamps, `-f` forces jobs, and `-n` runs jobs immediately,
so only `-T` belongs in a non-mutating fixture oracle ([`anacron.8`](https://github.com/cronie-crond/cronie/blob/71894fee3c74f3787e77f21a24fbbe0dffb59e7f/man/anacron.8),
[`main.c`](https://github.com/cronie-crond/cronie/blob/71894fee3c74f3787e77f21a24fbbe0dffb59e7f/anacron/main.c)).

### Activity, permissions, and limits

Anacron stores one timestamp file per identifier in `/var/spool/anacron`. The
file contains exactly an eight-digit `YYYYMMDD` date plus newline after a
successful or failed job completion; the source updates it before reporting
the exit result. It therefore proves only a last-attempt day, not success,
exit code, or run count ([`anacron.8`](https://github.com/cronie-crond/cronie/blob/71894fee3c74f3787e77f21a24fbbe0dffb59e7f/man/anacron.8),
[`lock.c`](https://github.com/cronie-crond/cronie/blob/71894fee3c74f3787e77f21a24fbbe0dffb59e7f/anacron/lock.c),
[`runjob.c`](https://github.com/cronie-crond/cronie/blob/71894fee3c74f3787e77f21a24fbbe0dffb59e7f/anacron/runjob.c)).

The implementation opens a timestamp `O_RDWR|O_CREAT`, sets owner/mode 0600,
and takes an exclusive `fcntl(F_SETLK)` lock before deciding to run. A
read-only diagnostic must never call that path. It may read an existing 0600
timestamp only when permitted; absence is **Absent**, malformed length/date is
**Unknown**, and permission/descriptor failure is **Unavailable**. A lock
probe using `F_GETLK` is optional and inherently a snapshot; inability to
inspect it is **Unknown**, not “idle” ([`lock.c`](https://github.com/cronie-crond/cronie/blob/71894fee3c74f3787e77f21a24fbbe0dffb59e7f/anacron/lock.c)).

Anacron is a one-shot process that normally forks and exits after jobs finish;
the official interface has no persistent daemon status query. Runtime and
current activity are therefore **Unknown** without an external service-manager
claim, and `LastResult` remains **Unknown** even when a timestamp exists
([`anacron.8`](https://github.com/cronie-crond/cronie/blob/71894fee3c74f3787e77f21a24fbbe0dffb59e7f/man/anacron.8),
[`main.c`](https://github.com/cronie-crond/cronie/blob/71894fee3c74f3787e77f21a24fbbe0dffb59e7f/anacron/main.c)).
The timestamp and spool paths are normally root-owned; an unprivileged
current-user probe should not attempt to read all users’ timestamp files.

## fcron 3.4.0 and 3.4.1

### Configuration and schedule

`fcron.conf` defines absolute `fcrontabs`, `pidfile`, and `fifofile` paths.
Each installed table has a human-readable `<user>.orig` source and a generated
non-human-readable `new.<user>` daemon file; the latter stores runtime data such
as next execution and is explicitly not a user-editable format ([`fcron.conf.5`](https://github.com/yo8192/fcron/blob/8198d4b90690fb0f53cca931b6e9bb6d4b9e6f83/doc/en/fcron.conf.5.sgml),
[`fcrontab.1`](https://github.com/yo8192/fcron/blob/8198d4b90690fb0f53cca931b6e9bb6d4b9e6f83/doc/en/fcrontab.1.sgml),
[`fcrontab.c`](https://github.com/yo8192/fcron/blob/8198d4b90690fb0f53cca931b6e9bb6d4b9e6f83/fcrontab.c)).

The source grammar includes elapsed-uptime (`@`), calendar (`&`), periodic
(`%`), environment assignments, inherited `!` options, timezone/DST handling,
randomization, jitter, boot/resume behavior, load-average and serial queues,
and reset/override rules ([`fcrontab.5`](https://github.com/yo8192/fcron/blob/8198d4b90690fb0f53cca931b6e9bb6d4b9e6f83/doc/en/fcrontab.5.sgml)).
This is a provider-native semantic model, not a five-field Cron projection.

### Runtime and hard blocker

The configured `fifofile` is used as a Unix-domain stream socket. `fcrondyn`
speaks a versioned-in-source binary command protocol and returns human text
fields such as ID, USER, PID, queue state, schedule, and CMD; the source also
contains mutating `run`, `runnow`, `kill`, and `renice` commands ([`fcrondyn.1`](https://github.com/yo8192/fcron/blob/8198d4b90690fb0f53cca931b6e9bb6d4b9e6f83/doc/en/fcrondyn.1.sgml),
[`dyncom.h`](https://github.com/yo8192/fcron/blob/8198d4b90690fb0f53cca931b6e9bb6d4b9e6f83/dyncom.h),
[`fcrondyn_svr.c`](https://github.com/yo8192/fcron/blob/8198d4b90690fb0f53cca931b6e9bb6d4b9e6f83/fcrondyn_svr.c)).
The issue safety boundary forbids both this socket/FIFO seam and compiled-spool
heuristics. Therefore fcron `Runtime`, `Activity`, `Runs`, and `LastResult`
must be **Unknown**; do not downgrade them to Absent.

The read-only source seam is `<user>.orig` for the caller’s own table. `-u`
selects another user or the system table and is documented for root; all-user
`fcrondyn ls` is root-only. `fcron.allow`, `fcron.deny`, PAM, socket
credentials, and (on some builds) password authentication can all deny access
([`fcrontab.1`](https://github.com/yo8192/fcron/blob/8198d4b90690fb0f53cca931b6e9bb6d4b9e6f83/doc/en/fcrontab.1.sgml),
[`fcrondyn.1`](https://github.com/yo8192/fcron/blob/8198d4b90690fb0f53cca931b6e9bb6d4b9e6f83/doc/en/fcrondyn.1.sgml),
[`fcrondyn_svr.c`](https://github.com/yo8192/fcron/blob/8198d4b90690fb0f53cca931b6e9bb6d4b9e6f83/fcrondyn_svr.c)).
No user switching or NSS enumeration is allowed in the adapter; system and
all-user scopes are consequently **Partial/Unavailable** unless an explicit,
pre-enumerated evidence input is supplied.

The 3.4.1 source records a separate release with fcrontab parser fixes and
fcrondyn output/error changes, including a distinct temporary-serialization
option label. A version-only check is insufficient; keep 3.4.0 and 3.4.1 as
separate ContractPins ([3.4.0 changes](https://github.com/yo8192/fcron/blob/8198d4b90690fb0f53cca931b6e9bb6d4b9e6f83/doc/en/changes.sgml),
[3.4.1 changes](https://github.com/yo8192/fcron/blob/a9c1590d9bf8b3ab3b13bba1d2777c7eb3ea6130/doc/en/changes.sgml)).

## Claim matrix

| Provider | Configuration | Runtime | Schedule | Activity | Runs / LastResult | Command |
| --- | --- | --- | --- | --- | --- | --- |
| Cronie | regular `/etc/crontab`, `/etc/cron.d`, or spool source; `PresentEmpty` is valid | Unknown unless pinned service-manager evidence | typed Cron grammar; `cronnext` is fixture oracle only | Unknown; no provider status API | Unknown | only exact Nix mapping can make it Known |
| Anacron | valid `/etc/anacrontab`; timestamp file is separate evidence | Unknown unless pinned service-manager evidence | typed period/delay/range/random grammar | timestamp day only; lock snapshot optional | last-attempt day only; result/count Unknown | only exact Nix mapping can make it Known |
| fcron | caller-readable `<user>.orig`; never `new.*` | Unknown under socket/FIFO ban | typed fcron-native grammar | Unknown under socket/compiled-spool ban | Unknown under socket/compiled-spool ban | only exact Nix mapping can make it Known |

`Configuration=Absent` means the expected regular source is missing. `Absent`
does not mean disabled: an inaccessible path, malformed source, unsupported
encoding, unsafe mode/owner, failed generation check, unavailable manager, or
forbidden runtime seam is `Unavailable` or `Unknown` as shown above.

## Fixtures and disposable VM coverage

The fixture matrix must use fixed source pins and must separate setup mutation
from diagnostic execution. Setup may create isolated files, users, and service
units; the diagnostic process itself must only read and must never invoke
`crontab`, `fcrontab`, `anacron -u`, `anacron -f`, fcrondyn mutators, signals, or
GC commands.

1. **Cronie source fixtures:** `/etc/crontab`, one `/etc/cron.d` file, current
   user spool, two all-user spool entries, empty table, missing table, wrong
   mode/owner, symlink, FIFO/device, malformed line, invalid UTF-8, and a
   helper that changes the file between pre/post metadata reads. Run the
   read-only adapter as an unprivileged observer and as root in separate VM
   cases; do not use `crontab -u`.
2. **Cronie schedule oracle:** use `cronnext -V` and `cronnext -s` only as
   pinned fixture assertions. Verify DST, `CRON_TZ`, tilde ranges, random delay,
   `/etc/cron.d` username fields, and the absence of an official runtime query
   ([`cronnext.1`](https://github.com/cronie-crond/cronie/blob/71894fee3c74f3787e77f21a24fbbe0dffb59e7f/man/cronnext.1)).
3. **Anacron fixtures:** valid/empty/missing `/etc/anacrontab`, named periods,
   continuation, range/random options, malformed/non-UTF-8 input, missing or
   malformed `YYYYMMDD\n` timestamp, inaccessible 0600 timestamp, and a
   test-only competing lock. `anacron -T` is the parser oracle; never use
   `-u`, `-f`, or `-n` in diagnostics ([`anacron.8`](https://github.com/cronie-crond/cronie/blob/71894fee3c74f3787e77f21a24fbbe0dffb59e7f/man/anacron.8)).
4. **fcron fixtures:** one caller-readable `<user>.orig`, empty/missing source,
   inherited/global options, uptime/calendar/periodic lines, random/jitter,
   timezone, boot/resume, malformed/non-UTF-8 input, and changed-generation
   input. Explicitly include `new.<user>`, `rm.<user>`, and `fifofile` as
   forbidden inputs; their presence must not become evidence of runtime.
5. **VM integration:** pin Nixpkgs `6cdc7fc...`, Cronie package 1.7.2 and its
   source/patch hashes, and fcron 3.4.0 package/module. For Cronie use an
   isolated systemd unit running `crond -n -i` with future-only tables; for
   fcron use the official NixOS module only to provision a disposable daemon,
   then assert the adapter never opens its socket or compiled spool. Anacron
   uses the pinned Cronie package and a static `/etc/anacrontab`; do not start a
   job runner. Restrict network, disable forwarding, and keep GC commands out
   of all fixture tables.

Unexecuted on this macOS research host: the VM matrix, permission-denial cases,
in-flight replacement, and platform-specific daemon states. These are required
CI checks, not observations claimed by this asset.

## Implementation consequence for #32

Issue #32 is not implementation-ready as one ticket under its current safety
boundary. Split the work into:

* a file-only Cronie/Anacron configuration-and-schedule adapter with explicit
  `Unknown` runtime/activity/result claims;
* a fcron source-table parser restricted to `<user>.orig`, with 3.4.0 and 3.4.1
  catalog entries and no socket/compiled-spool support; and
* a separate, optional service-manager research ticket if Runtime claims are
  required. That ticket must define a pinned systemd/launchd authority and
  never use PID heuristics.

No generic Cronie/Anacron/fcron observation may be promoted to Nix GC
`AutomationMapping` without a fixed Nix/NixOS authority fingerprint. The
remaining provider gaps are therefore explicit `Unknown`/`Unavailable` states,
not guessed defaults.
