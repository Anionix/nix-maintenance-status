use std::fmt;
use std::time::Duration;

use crate::catalog::{
    AuthorityResolution, AuthorityRole, AuthorityUnknownReason, CatalogScope,
    ObservedAuthorityIdentity, ProviderCatalog,
};
use crate::evidence::{
    CaptureSequence, DefinitionOccurrence, DefinitionShape, ExecutionContext, InputError,
    ObservationComponent, ObservationUnknownReason, Presence, Provider, ProviderEvidence,
    ProviderEvidenceSet, ProviderLogicalKey, ShapeState, ShapeUnknownReason, SourceOccurrenceKey,
    SourceRoot, SourceRootId, Subject, SystemdManagerIdentity, SystemdUnitId, UnavailableReason,
};
use crate::report::{Schedule, SystemdSchedule, SystemdTimerPolicy, SystemdTrigger};

pub const NIX_GC_TIMER: &str = "nix-gc.timer";
pub const NIX_GC_SERVICE: &str = "nix-gc.service";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SystemdCommandUnknownReason {
    MalformedExecStart,
    WrapperUnavailable,
    WrapperMismatch,
    NonGcCommand,
    NonUtf8,
    AmbiguousShell,
    OverrideDetected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SystemdAuthorityUnknownReason {
    VersionUnknown,
    NixpkgsUnknown,
    PackageUnknown,
    PatchSetUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemdAuthorityIdentity(AuthorityResolution);

impl SystemdAuthorityIdentity {
    // LLM contract: only an adapter-owned, catalog-resolved systemd contract
    // can create this token. Version/package/patch mismatches stay Unknown;
    // callers cannot manufacture an Authority or upgrade a report.
    #[allow(dead_code)]
    pub(crate) fn from_pins(
        systemd_version: &str,
        nixpkgs_revision: &str,
        package_digest: &str,
        patch_digest: &str,
    ) -> Result<Self, SystemdAuthorityUnknownReason> {
        if systemd_version != "261" {
            return Err(SystemdAuthorityUnknownReason::VersionUnknown);
        }
        let mapping = ProviderCatalog::embedded()
            .entries()
            .iter()
            .find(|entry| entry.entry_id().as_str() == "nixos.gc.mapping.v1")
            .expect("embedded NixOS mapping authority");
        let integrity = mapping.integrity();
        if nixpkgs_revision != integrity[0].source().revision().as_str() {
            return Err(SystemdAuthorityUnknownReason::NixpkgsUnknown);
        }
        if package_digest != integrity[0].digest() {
            return Err(SystemdAuthorityUnknownReason::PackageUnknown);
        }
        if patch_digest != integrity[1].digest() {
            return Err(SystemdAuthorityUnknownReason::PatchSetUnknown);
        }
        Self::from_version(systemd_version).ok_or(SystemdAuthorityUnknownReason::VersionUnknown)
    }

    // LLM contract: the version is a normalized Manager.Version observation;
    // only the embedded systemd.v261.dbus.v1 ContractPin creates identity.
    // Unknown/malformed versions never become Authority and no I/O occurs.
    #[allow(dead_code)]
    pub(crate) fn from_version(version: &str) -> Option<Self> {
        let identity = ObservedAuthorityIdentity::contract_with_fingerprint(
            "systemd",
            "de9dbc37ad4aa637e200ac02a0545095997055df",
            "org.freedesktop.systemd1.xml",
            Some(version),
            None,
            Some("systemd-v261-dbus-v1"),
        )
        .ok()?;
        let resolution = ProviderCatalog::embedded().resolve(
            AuthorityRole::SchedulerSemantics,
            CatalogScope::Provider(Provider::NixOsSystemd),
            &identity,
        );
        matches!(
            resolution,
            AuthorityResolution::Resolved(reference)
                if reference.entry_id().as_str() == "systemd.v261.dbus.v1"
        )
        .then_some(Self(resolution))
    }

    pub(crate) const fn resolution(self) -> AuthorityResolution {
        self.0
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SystemdExecStart {
    executable: String,
}

impl fmt::Debug for SystemdExecStart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<opaque>")
    }
}

impl SystemdExecStart {
    /// Normalize the exact systemd `ExecStart` read signature
    /// `a(sasbttttuii)`. The raw path/argv remain adapter-local and Debug never
    /// exposes them.
    #[allow(dead_code)]
    pub(crate) fn from_read_signature(
        executable: &str,
        argv: &[String],
        ignore_failure: bool,
    ) -> Result<Self, SystemdCommandUnknownReason> {
        if ignore_failure
            || executable.is_empty()
            || argv.len() != 1
            || argv.first().is_none_or(|value| value != executable)
            || executable.chars().any(char::is_control)
            || argv[0].len() > 1024
            || argv[0].chars().any(char::is_control)
        {
            return Err(SystemdCommandUnknownReason::MalformedExecStart);
        }
        Ok(Self {
            executable: executable.to_owned(),
        })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn executable(&self) -> &str {
        &self.executable
    }

    #[allow(dead_code)]
    fn is_generated_wrapper(&self) -> bool {
        is_safe_store_path(&self.executable)
            && self
                .executable
                .ends_with("-unit-script-nix-gc-start/bin/nix-gc-start")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SystemdCommandIdentity(CommandIdentityKind);

impl fmt::Debug for SystemdCommandIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<opaque>")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum CommandIdentityKind {
    NixCollectGarbage,
    Unknown(SystemdCommandUnknownReason),
    Unavailable(UnavailableReason),
}

impl SystemdCommandIdentity {
    #[allow(dead_code)]
    pub(crate) const fn unknown(reason: SystemdCommandUnknownReason) -> Self {
        Self(CommandIdentityKind::Unknown(reason))
    }

    const fn unavailable(reason: UnavailableReason) -> Self {
        Self(CommandIdentityKind::Unavailable(reason))
    }

    pub const fn is_exact(self) -> bool {
        matches!(self.0, CommandIdentityKind::NixCollectGarbage)
    }

    const fn is_non_gc_override(self) -> bool {
        matches!(
            self.0,
            CommandIdentityKind::Unknown(
                SystemdCommandUnknownReason::OverrideDetected
                    | SystemdCommandUnknownReason::NonGcCommand
            )
        )
    }

    // LLM contract: Exact is Present. A readable non-exact wrapper is
    // Unknown, while wrapper transport/encoding failures are Unavailable;
    // neither state becomes Absent.
    pub const fn presence(self) -> Presence {
        match self {
            Self(CommandIdentityKind::NixCollectGarbage) => Presence::Present,
            Self(CommandIdentityKind::Unknown(reason)) => match reason {
                SystemdCommandUnknownReason::WrapperUnavailable => {
                    Presence::Unavailable(UnavailableReason::InterfaceUnavailable)
                }
                SystemdCommandUnknownReason::NonUtf8 => {
                    Presence::Unavailable(UnavailableReason::UnsupportedEncoding)
                }
                SystemdCommandUnknownReason::MalformedExecStart
                | SystemdCommandUnknownReason::WrapperMismatch
                | SystemdCommandUnknownReason::NonGcCommand
                | SystemdCommandUnknownReason::AmbiguousShell
                | SystemdCommandUnknownReason::OverrideDetected => {
                    Presence::Unknown(ObservationUnknownReason::UnsupportedSyntax)
                }
            },
            Self(CommandIdentityKind::Unavailable(reason)) => Presence::Unavailable(reason),
        }
    }
}

// LLM contract: one pinned four-line generated wrapper plus one safe `exec`
// command is exact; overrides, shell syntax, malformed bytes, and unavailable
// wrappers remain Unknown. Raw command text never crosses the evidence boundary.
#[allow(dead_code)]
pub(crate) fn classify_nix_gc_command(
    exec_start: &SystemdExecStart,
    wrapper: Result<&[u8], SystemdBusError>,
) -> SystemdCommandIdentity {
    if !exec_start.is_generated_wrapper() {
        return SystemdCommandIdentity::unknown(SystemdCommandUnknownReason::OverrideDetected);
    }
    let bytes = match wrapper {
        Ok(bytes) => bytes,
        Err(error) => {
            let reason = match error.presence() {
                Presence::Unavailable(reason) => reason,
                _ => UnavailableReason::InterfaceUnavailable,
            };
            return SystemdCommandIdentity::unavailable(reason);
        }
    };
    let script = match std::str::from_utf8(bytes) {
        Ok(script) => script,
        Err(_) => return SystemdCommandIdentity::unknown(SystemdCommandUnknownReason::NonUtf8),
    };
    if script.is_empty()
        || !script.ends_with('\n')
        || script
            .bytes()
            .any(|byte| byte != b'\n' && !(0x20..=0x7e).contains(&byte))
    {
        return SystemdCommandIdentity::unknown(SystemdCommandUnknownReason::WrapperMismatch);
    }
    // NixOS's writeShellScriptBin appends one template newline after the
    // script's own final newline. Accept that exact two-newline form (or the
    // one-newline form used by hand-built fixtures), but reject extra lines.
    let script = &script[..script.len() - 1];
    let script = script.strip_suffix('\n').unwrap_or(script);
    let lines: Vec<_> = script.split('\n').collect();
    let command_line = match lines.as_slice() {
        [shebang, strict, blank, command]
            if is_pinned_shebang(shebang) && *strict == "set -e" && blank.is_empty() =>
        {
            *command
        }
        _ => "",
    };
    if !command_line.starts_with("exec ") {
        return SystemdCommandIdentity::unknown(SystemdCommandUnknownReason::WrapperMismatch);
    }
    let mut words = command_line[5..].split_whitespace();
    let Some(command) = words.next() else {
        return SystemdCommandIdentity::unknown(SystemdCommandUnknownReason::WrapperMismatch);
    };
    if !is_nix_collect_garbage_path(command) {
        return SystemdCommandIdentity::unknown(SystemdCommandUnknownReason::NonGcCommand);
    }
    let mut options = words.peekable();
    while let Some(option) = options.next() {
        let needs_value = matches!(option, "--delete-older-than" | "--max-freed");
        if !matches!(
            option,
            "--delete-old" | "--delete-older-than" | "--max-freed" | "--dry-run"
        ) || !safe_gc_option(option)
        {
            return SystemdCommandIdentity::unknown(SystemdCommandUnknownReason::AmbiguousShell);
        }
        if needs_value {
            let Some(value) = options.next() else {
                return SystemdCommandIdentity::unknown(
                    SystemdCommandUnknownReason::AmbiguousShell,
                );
            };
            let valid = match option {
                "--delete-older-than" => safe_gc_age(value),
                "--max-freed" => safe_gc_bytes(value),
                _ => false,
            };
            if !valid {
                return SystemdCommandIdentity::unknown(
                    SystemdCommandUnknownReason::AmbiguousShell,
                );
            }
        }
    }
    SystemdCommandIdentity(CommandIdentityKind::NixCollectGarbage)
}

#[allow(dead_code)]
pub(crate) fn is_safe_store_path(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("/nix/store/") else {
        return false;
    };
    let mut parts = rest.split('/');
    let Some(object) = parts.next() else {
        return false;
    };
    let Some((hash, name)) = object.split_once('-') else {
        return false;
    };
    valid_store_hash(hash)
        && !name.is_empty()
        && parts.all(|part| !part.is_empty() && part != "." && part != "..")
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'+' | b'-')
        })
}

#[allow(dead_code)]
fn store_object_name(value: &str) -> Option<&str> {
    value
        .strip_prefix("/nix/store/")?
        .split('/')
        .next()?
        .split_once('-')
        .map(|(_, name)| name)
}

#[allow(dead_code)]
fn is_nix_collect_garbage_path(value: &str) -> bool {
    is_safe_store_path(value)
        && value.ends_with("/bin/nix-collect-garbage")
        && store_object_name(value).is_some_and(|name| name.starts_with("nix-"))
}

#[allow(dead_code)]
fn valid_store_hash(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte))
}

#[allow(dead_code)]
fn is_pinned_shebang(value: &str) -> bool {
    value.strip_prefix("#!").is_some_and(|path| {
        is_safe_store_path(path)
            && path.ends_with("/bin/bash")
            && store_object_name(path).is_some_and(|name| name.starts_with("bash-"))
    })
}

#[allow(dead_code)]
fn safe_gc_option(value: &str) -> bool {
    matches!(
        value,
        "--delete-old" | "--delete-older-than" | "--max-freed" | "--dry-run"
    )
}

#[allow(dead_code)]
fn safe_gc_age(value: &str) -> bool {
    let Some(unit) = value.chars().last() else {
        return false;
    };
    matches!(unit, 's' | 'm' | 'h' | 'd' | 'w' | 'M' | 'y')
        && bounded_digits(&value[..value.len() - unit.len_utf8()])
}

#[allow(dead_code)]
fn safe_gc_bytes(value: &str) -> bool {
    let (digits, suffix) = value
        .strip_suffix(|byte: char| matches!(byte, 'K' | 'M' | 'G' | 'T'))
        .map_or((value, None), |digits| (digits, value.chars().last()));
    suffix.is_none_or(|_| !digits.is_empty()) && bounded_digits(digits)
}

#[allow(dead_code)]
fn bounded_digits(value: &str) -> bool {
    !value.is_empty() && value.len() <= 20 && value.bytes().all(|byte| byte.is_ascii_digit())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SystemdBusError {
    AccessDenied,
    Disconnected,
    ServiceUnknown,
    NameHasNoOwner,
    NoSuchUnit,
    NoReply,
    InvalidSignature,
    UnknownMethod,
    ResourceLimitExceeded,
    OperationFailed,
}

impl SystemdBusError {
    // LLM contract: this mapping never produces Absent; only the exact
    // nix-gc helper may interpret NoSuchUnit as finite absence. Other errors
    // remain Unavailable with a stable reason and no raw text.
    pub const fn presence(self) -> Presence {
        match self {
            // A no-unit response is Absent only after the caller has selected
            // the finite catalogued identity in `normalize_nix_gc_state`.
            Self::NoSuchUnit => Presence::Unavailable(UnavailableReason::OperationFailed),
            Self::AccessDenied => Presence::Unavailable(UnavailableReason::PermissionDenied),
            Self::NoReply => Presence::Unavailable(UnavailableReason::TimedOut),
            Self::InvalidSignature | Self::UnknownMethod => {
                Presence::Unavailable(UnavailableReason::MalformedEvidence)
            }
            Self::ResourceLimitExceeded => {
                Presence::Unavailable(UnavailableReason::ResourceLimitExceeded)
            }
            Self::ServiceUnknown | Self::NameHasNoOwner | Self::Disconnected => {
                Presence::Unavailable(UnavailableReason::InterfaceUnavailable)
            }
            Self::OperationFailed => Presence::Unavailable(UnavailableReason::OperationFailed),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdTimerProperties {
    target: SystemdUnitId,
    triggers: Vec<SystemdTrigger>,
    policy: SystemdTimerPolicy,
}

impl SystemdTimerProperties {
    // LLM contract: valid typed triggers/policy transition to one immutable
    // property set; empty/unsafe schedules are rejected and no raw D-Bus value
    // or version guess enters the public schedule.
    pub fn new(
        target: SystemdUnitId,
        triggers: Vec<SystemdTrigger>,
        policy: SystemdTimerPolicy,
    ) -> Result<Self, InputError> {
        SystemdSchedule::new(triggers.clone(), policy)
            .map_err(|_| InputError::InvalidNormalizedValue)?;
        Ok(Self {
            target,
            triggers,
            policy,
        })
    }

    pub const fn target(&self) -> &SystemdUnitId {
        &self.target
    }

    pub fn schedule(&self) -> Schedule {
        Schedule::Systemd(
            SystemdSchedule::new(self.triggers.clone(), self.policy)
                .expect("validated systemd properties remain valid"),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdBusSnapshot {
    manager: SystemdManagerIdentity,
    subject: Subject,
    unit: SystemdUnitId,
    source: SourceRootId,
    capture: CaptureSequence,
    configured: Presence,
    loaded: Presence,
    generation: Option<(u64, u64)>,
    properties: Result<Option<SystemdTimerProperties>, SystemdBusError>,
    command: Result<Option<SystemdCommandIdentity>, SystemdBusError>,
    authority_identity: Option<SystemdAuthorityIdentity>,
}

impl SystemdBusSnapshot {
    // LLM contract: construction accepts one bounded typed transport result;
    // manager/subject identity is validated, and GetAll failures stay typed.
    // No D-Bus bytes, error strings, or raw XML cross this constructor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        manager: SystemdManagerIdentity,
        subject: Subject,
        unit: SystemdUnitId,
        source: SourceRootId,
        capture: CaptureSequence,
        configured: Presence,
        loaded: Presence,
        generation_before: u64,
        generation_after: u64,
        properties: Result<Option<SystemdTimerProperties>, SystemdBusError>,
    ) -> Result<Self, InputError> {
        Self::from_generation(
            manager,
            subject,
            unit,
            source,
            capture,
            configured,
            loaded,
            Some((generation_before, generation_after)),
            properties,
        )
    }

    /// Construct a snapshot when the provider exposes no stable read-generation.
    /// The absence is explicit so normalization never treats a sentinel as an
    /// observed consistency proof.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn without_generation(
        manager: SystemdManagerIdentity,
        subject: Subject,
        unit: SystemdUnitId,
        source: SourceRootId,
        capture: CaptureSequence,
        configured: Presence,
        loaded: Presence,
        properties: Result<Option<SystemdTimerProperties>, SystemdBusError>,
    ) -> Result<Self, InputError> {
        Self::from_generation(
            manager, subject, unit, source, capture, configured, loaded, None, properties,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_generation(
        manager: SystemdManagerIdentity,
        subject: Subject,
        unit: SystemdUnitId,
        source: SourceRootId,
        capture: CaptureSequence,
        configured: Presence,
        loaded: Presence,
        generation: Option<(u64, u64)>,
        properties: Result<Option<SystemdTimerProperties>, SystemdBusError>,
    ) -> Result<Self, InputError> {
        if (manager == SystemdManagerIdentity::System && subject != Subject::System)
            || (manager == SystemdManagerIdentity::User && !matches!(subject, Subject::Uid(_)))
        {
            return Err(InputError::InvalidSubject);
        }
        Ok(Self {
            manager,
            subject,
            unit,
            source,
            capture,
            configured,
            loaded,
            generation,
            properties,
            command: Ok(None),
            authority_identity: None,
        })
    }

    // LLM contract: attach one adapter-normalized command result; replacing
    // it never performs I/O or upgrades Unknown into an exact identity.
    #[allow(dead_code)]
    pub(crate) fn with_command(
        mut self,
        command: Result<Option<SystemdCommandIdentity>, SystemdBusError>,
    ) -> Self {
        self.command = command;
        self
    }

    // LLM contract: only an adapter-observed systemd token can attach to a
    // snapshot; None preserves Unknown and cannot be upgraded by a caller.
    #[allow(dead_code)]
    pub(crate) fn with_authority_identity(
        mut self,
        identity: Option<SystemdAuthorityIdentity>,
    ) -> Self {
        self.authority_identity = identity;
        self
    }

    pub(crate) const fn generation_changed(&self) -> bool {
        matches!(self.generation, Some((before, after)) if before != after)
    }

    pub(crate) const fn generation_attested(&self) -> bool {
        self.generation.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdNormalizedObservation {
    evidence: ProviderEvidenceSet,
    authority: AuthorityResolution,
}

impl SystemdNormalizedObservation {
    pub fn evidence(&self) -> &ProviderEvidenceSet {
        &self.evidence
    }
    pub const fn authority(&self) -> AuthorityResolution {
        self.authority
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SystemdAdapterError {
    InvalidInput(InputError),
}

/// Normalize the exact catalogued `nix-gc.timer` lookup. `NoSuchUnit` is only
/// Absent for this finite identity; other manager/interface failures remain
/// Unavailable through `SystemdBusError::presence`.
// LLM contract: Ok(false)/NoSuchUnit -> Absent, Ok(true) -> Present, every
// other error -> Unavailable; no arbitrary unit identity is accepted here.
pub fn normalize_nix_gc_state(result: Result<bool, SystemdBusError>) -> Presence {
    match result {
        Err(SystemdBusError::NoSuchUnit) | Ok(false) => Presence::Absent,
        Err(error) => error.presence(),
        Ok(true) => Presence::Present,
    }
}

// LLM contract: only an exact observed Nixpkgs revision is resolved against
// the embedded mapping fingerprint. Callers cannot supply the fingerprint or
// an AuthorityResolution, and misses remain Unresolved without network/I/O.
pub fn resolve_nix_gc_authority(revision: &str) -> AuthorityResolution {
    let identity = match ObservedAuthorityIdentity::source_with_fingerprint(
        "NixOS/nixpkgs",
        revision,
        Some("nixos-gc-systemd-mapping-v1"),
    ) {
        Ok(identity) => identity,
        Err(_) => {
            return AuthorityResolution::Unresolved(AuthorityUnknownReason::IdentityMalformed);
        }
    };
    ProviderCatalog::embedded().resolve(
        AuthorityRole::AutomationMapping,
        CatalogScope::Provider(Provider::NixOsSystemd),
        &identity,
    )
}

fn resolve_nix_gc_operation_authority() -> AuthorityResolution {
    let identity = ObservedAuthorityIdentity::source_with_fingerprint(
        "NixOS/nix",
        "035f34f13f969cf72ca4ea60369d907972402956",
        Some("nix-gc-operation-v1"),
    )
    .expect("embedded Nix operation identity is valid");
    ProviderCatalog::embedded().resolve(
        AuthorityRole::GcOperationSemantics,
        CatalogScope::Nix,
        &identity,
    )
}

fn occurrence(snapshot: &SystemdBusSnapshot) -> DefinitionOccurrence {
    DefinitionOccurrence::new(
        ProviderLogicalKey::Systemd {
            manager: snapshot.manager,
            subject: snapshot.subject,
            canonical_timer_id: snapshot.unit.clone(),
        },
        SourceOccurrenceKey::new(SourceRoot::SystemdUnit(snapshot.source), 1),
        snapshot.capture.clone(),
    )
}

fn systemd_shape(
    properties: &SystemdTimerProperties,
    changed: bool,
    generation_attested: bool,
) -> DefinitionShape {
    // LLM contract: stable properties map to Known; changed/unattested map to
    // typed Unavailable; command/context stay capability-limited. No I/O.
    let (schedule, target) = if changed {
        (
            ShapeState::Unavailable(UnavailableReason::ChangedDuringRead),
            ShapeState::Unavailable(UnavailableReason::ChangedDuringRead),
        )
    } else if !generation_attested {
        (
            ShapeState::Unavailable(UnavailableReason::ConsistencyNotAttested),
            ShapeState::Unavailable(UnavailableReason::ConsistencyNotAttested),
        )
    } else {
        (
            ShapeState::Known(match properties.schedule() {
                Schedule::Systemd(schedule) => schedule,
                _ => unreachable!("systemd properties yield systemd schedule"),
            }),
            ShapeState::Known(properties.target().clone()),
        )
    };
    DefinitionShape::Systemd {
        schedule,
        target,
        command: ShapeState::Unknown(ShapeUnknownReason::Incomplete),
        context: ShapeState::Known(ExecutionContext::System),
    }
}

// LLM contract: normalization is triggered by one typed, bounded snapshot.
// LLM contract: a system nix-gc.timer/service target admits a structural
// candidate before command attribution. Exact command and Authority govern
// claim officiality/consistency, so Unknown never erases inventory membership.
// NoSuchUnit is Absent only for the finite helper, all other bus failures stay
// Unavailable, and no path performs I/O, retries, mutation, telemetry, or GC.
// A transport without an official read-generation supplies no consistency
// attestation; it cannot create an identity or expose a schedule as usable.
pub fn normalize_systemd_snapshot(
    snapshot: SystemdBusSnapshot,
    nixpkgs_revision: &str,
) -> Result<SystemdNormalizedObservation, SystemdAdapterError> {
    let observed_authority = if snapshot.manager == SystemdManagerIdentity::System {
        resolve_nix_gc_authority(nixpkgs_revision)
    } else {
        AuthorityResolution::NotApplicable
    };
    let operation_authority = resolve_nix_gc_operation_authority();
    let scheduler_authority = snapshot.authority_identity.map_or(
        AuthorityResolution::Unresolved(AuthorityUnknownReason::IdentityUnavailable),
        SystemdAuthorityIdentity::resolution,
    );
    let expected_timer =
        SystemdUnitId::new(NIX_GC_TIMER).expect("catalogued Nix timer identity is valid");
    let expected_service =
        SystemdUnitId::new(NIX_GC_SERVICE).expect("catalogued Nix service identity is valid");
    let changed = snapshot.generation_changed();
    let generation_attested = snapshot.generation_attested();
    let unstable = changed || !generation_attested;
    let structural_identity = snapshot.manager == SystemdManagerIdentity::System
        && snapshot.unit == expected_timer
        && matches!(
            snapshot.properties.as_ref(),
            Ok(Some(properties)) if properties.target() == &expected_service
        )
        && !matches!(snapshot.command, Ok(Some(command)) if command.is_non_gc_override());
    let occurrence = if structural_identity {
        let properties = match &snapshot.properties {
            Ok(Some(properties)) => properties,
            _ => unreachable!("structural identity requires timer properties"),
        };
        Some(
            occurrence(&snapshot)
                .with_shape(systemd_shape(properties, changed, generation_attested))
                .map_err(SystemdAdapterError::InvalidInput)?,
        )
    } else {
        None
    };
    let authority = if structural_identity {
        observed_authority
    } else if snapshot.manager == SystemdManagerIdentity::User {
        AuthorityResolution::NotApplicable
    } else {
        match observed_authority {
            AuthorityResolution::Resolved(_) => {
                AuthorityResolution::Unresolved(AuthorityUnknownReason::ExactBasisUnverifiable)
            }
            other => other,
        }
    };
    let authorities = [operation_authority, authority, scheduler_authority];
    let unavailable = Presence::Unavailable(UnavailableReason::ChangedDuringRead);
    let configuration = if changed {
        unavailable
    } else {
        snapshot.configured
    };
    let runtime = if changed {
        unavailable
    } else {
        snapshot.loaded
    };
    let mut entries = vec![
        make_evidence(
            ObservationComponent::Configuration,
            configuration,
            snapshot.subject,
            occurrence.as_ref(),
            authorities,
        )?,
        make_evidence(
            ObservationComponent::Runtime,
            runtime,
            snapshot.subject,
            occurrence.as_ref(),
            authorities,
        )?,
    ];
    if snapshot.manager == SystemdManagerIdentity::System {
        let command_presence = if changed {
            Presence::Unavailable(UnavailableReason::ChangedDuringRead)
        } else {
            match snapshot.command {
                Ok(Some(command)) => command.presence(),
                Ok(None) => Presence::Unavailable(UnavailableReason::MalformedEvidence),
                Err(error) => error.presence(),
            }
        };
        entries.push(make_evidence(
            ObservationComponent::Command,
            command_presence,
            snapshot.subject,
            occurrence.as_ref(),
            authorities,
        )?);
    }
    if unstable || runtime == Presence::Present || !matches!(&snapshot.properties, Ok(None)) {
        let schedule_presence = if changed {
            Presence::Unavailable(UnavailableReason::ChangedDuringRead)
        } else if !generation_attested {
            Presence::Unavailable(UnavailableReason::ConsistencyNotAttested)
        } else {
            match &snapshot.properties {
                Ok(Some(_)) => Presence::Present,
                Ok(None) => Presence::Unavailable(UnavailableReason::MalformedEvidence),
                Err(error) => error.presence(),
            }
        };
        let evidence = make_evidence(
            ObservationComponent::Schedule,
            schedule_presence,
            snapshot.subject,
            occurrence.as_ref(),
            authorities,
        )?;
        entries.push(if !unstable {
            if let Ok(Some(properties)) = snapshot.properties {
                if schedule_presence == Presence::Present {
                    evidence
                        .with_schedule(properties.schedule())
                        .map_err(SystemdAdapterError::InvalidInput)?
                } else {
                    evidence
                }
            } else {
                evidence
            }
        } else {
            evidence
        });
    }
    let evidence = ProviderEvidenceSet::new(entries).map_err(SystemdAdapterError::InvalidInput)?;
    Ok(SystemdNormalizedObservation {
        evidence,
        authority,
    })
}

fn make_evidence(
    // LLM contract: one component receives only its role's normalized
    // Authority; duplicate, mismatched, or unclaimed transitions stay safe.
    component: ObservationComponent,
    presence: Presence,
    subject: Subject,
    occurrence: Option<&DefinitionOccurrence>,
    authorities: [AuthorityResolution; 3],
) -> Result<ProviderEvidence, SystemdAdapterError> {
    let evidence = occurrence.map_or_else(
        || {
            ProviderEvidence::new(Provider::NixOsSystemd, subject, component, presence)
                .map_err(SystemdAdapterError::InvalidInput)
        },
        |occurrence| {
            ProviderEvidence::with_occurrence(
                Provider::NixOsSystemd,
                subject,
                component,
                presence,
                occurrence.clone(),
            )
            .map_err(SystemdAdapterError::InvalidInput)
        },
    )?;
    let role = match component {
        ObservationComponent::Configuration => Some(AuthorityRole::AutomationMapping),
        ObservationComponent::Runtime | ObservationComponent::Schedule => {
            Some(AuthorityRole::SchedulerSemantics)
        }
        ObservationComponent::Command => Some(AuthorityRole::GcOperationSemantics),
        _ => None,
    };
    match role {
        None => Ok(evidence),
        Some(role) => evidence
            .with_authority(role, authorities[role.index()])
            .map_err(SystemdAdapterError::InvalidInput),
    }
}

// LLM contract: every microsecond value maps exactly to a non-truncating
// Duration; conversion cannot fail and performs no I/O.
pub const fn duration_from_usec(usec: u64) -> Duration {
    let seconds = usec / 1_000_000;
    let micros = usec % 1_000_000;
    Duration::new(seconds, micros as u32 * 1_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    const STORE_HASH: &str = "0123456789abcdfghijklmnpqrsvwxyz";
    const FIXTURE_REVISION: &str = "6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee";
    const PACKAGE_DIGEST: &str = "e8807564442a4348a6a7006109a2d900480c56454553ad490d5946a2dc4dcc64";
    const PATCH_DIGEST: &str = "16689e241f3f394bcdc5b91ba22efe2067c8b925d8de717f859426f240f4af9d";

    fn generated_exec() -> SystemdExecStart {
        let path = format!("/nix/store/{STORE_HASH}-unit-script-nix-gc-start/bin/nix-gc-start");
        SystemdExecStart::from_read_signature(&path, std::slice::from_ref(&path), false).unwrap()
    }

    #[test]
    fn generated_wrapper_is_the_only_exact_command_identity() {
        let exec = generated_exec();
        assert!(classify_nix_gc_command(
            &exec,
            Ok(format!(
                "#!/nix/store/{STORE_HASH}-bash-5/bin/bash\nset -e\n\nexec /nix/store/{STORE_HASH}-nix-2.0/bin/nix-collect-garbage --delete-old\n\n"
            ).as_bytes()),
        ).is_exact());
        assert!(
            !classify_nix_gc_command(
                &exec,
                Ok(format!(
                    "#!/nix/store/{STORE_HASH}-bash-5/bin/bash\nset -e\n\nexec /bin/sh -c nix-collect-garbage\n"
                ).as_bytes()),
            )
            .is_exact()
        );
        assert!(
            !classify_nix_gc_command(
                &exec,
                Ok(format!(
                    "#!/nix/store/{STORE_HASH}-bash-5/bin/bash\nset -e\n\nexec /nix/store/{STORE_HASH}-nix-2.0/bin/nix-collect-garbage $(secret)\n"
                ).as_bytes()),
            )
            .is_exact()
        );
        assert!(!classify_nix_gc_command(
            &exec,
            Ok(format!(
                "#!/nix/store/{STORE_HASH}-bash-5/bin/bash\nexec /nix/store/{STORE_HASH}-nix-2.0/bin/nix-collect-garbage\n"
            ).as_bytes()),
        ).is_exact());
        assert!(!classify_nix_gc_command(
            &exec,
            Ok(format!(
                "#!/nix/store/{STORE_HASH}-bash-5/bin/bash\nset -e\n\nexec /nix/store/{STORE_HASH}-nix-2.0/bin/nix-collect-garbage --delete-older-than /tmp\n"
            ).as_bytes()),
        ).is_exact());
    }

    #[test]
    fn malformed_or_unavailable_wrappers_never_leak_raw_data() {
        let exec = generated_exec();
        assert!(!classify_nix_gc_command(&exec, Ok(&[0xffu8][..])).is_exact());
        assert!(!classify_nix_gc_command(&exec, Err(SystemdBusError::OperationFailed)).is_exact());
        assert!(!format!("{exec:?}").contains("nix-gc-start"));
    }

    #[test]
    fn wrapper_probe_errors_keep_typed_unavailable_reasons() {
        let exec = generated_exec();
        for (error, expected) in [
            (
                SystemdBusError::AccessDenied,
                UnavailableReason::PermissionDenied,
            ),
            (SystemdBusError::NoReply, UnavailableReason::TimedOut),
            (
                SystemdBusError::ResourceLimitExceeded,
                UnavailableReason::ResourceLimitExceeded,
            ),
            (
                SystemdBusError::InvalidSignature,
                UnavailableReason::MalformedEvidence,
            ),
            (
                SystemdBusError::OperationFailed,
                UnavailableReason::OperationFailed,
            ),
        ] {
            assert_eq!(
                classify_nix_gc_command(&exec, Err(error)).presence(),
                Presence::Unavailable(expected)
            );
        }
        assert_eq!(
            classify_nix_gc_command(&exec, Ok(b"#!/bin/sh\nset -e\n\nexec /bin/sh -c unknown\n"),)
                .presence(),
            Presence::Unknown(ObservationUnknownReason::UnsupportedSyntax)
        );
    }

    #[test]
    fn exact_authority_is_only_created_by_the_catalogued_version() {
        assert!(SystemdAuthorityIdentity::from_version("261").is_some());
        assert!(SystemdAuthorityIdentity::from_version("262").is_none());
    }

    #[test]
    fn exact_normalization_requires_internal_command_and_authority_seams() {
        let target = SystemdUnitId::new(NIX_GC_SERVICE).unwrap();
        let properties = SystemdTimerProperties::new(
            target,
            vec![SystemdTrigger::OnCalendar("03:15:00".to_owned())],
            SystemdTimerPolicy::new(None, None, false, None, false, false, false),
        )
        .unwrap();
        let path = format!("/nix/store/{STORE_HASH}-unit-script-nix-gc-start/bin/nix-gc-start");
        let exec = SystemdExecStart::from_read_signature(&path, std::slice::from_ref(&path), false)
            .unwrap();
        let command = classify_nix_gc_command(
            &exec,
            Ok(format!(
                "#!/nix/store/{STORE_HASH}-bash-5/bin/bash\nset -e\n\nexec /nix/store/{STORE_HASH}-nix-2.0/bin/nix-collect-garbage --delete-old\n"
            ).as_bytes()),
        );
        let snapshot = SystemdBusSnapshot::new(
            SystemdManagerIdentity::System,
            Subject::System,
            SystemdUnitId::new(NIX_GC_TIMER).unwrap(),
            SourceRootId::new(1),
            CaptureSequence::new(1),
            Presence::Present,
            Presence::Present,
            1,
            1,
            Ok(Some(properties.clone())),
        )
        .unwrap()
        .with_command(Ok(Some(command)))
        .with_authority_identity(Some(
            SystemdAuthorityIdentity::from_pins(
                "261",
                FIXTURE_REVISION,
                PACKAGE_DIGEST,
                PATCH_DIGEST,
            )
            .unwrap(),
        ));
        let report =
            normalize_systemd_snapshot(snapshot, "e8d924d50a462f89166e31a27bdcbbade35fd8e6")
                .unwrap();
        assert!(
            report
                .evidence()
                .entries()
                .iter()
                .all(|entry| entry.occurrence().is_some())
        );
        assert!(
            report
                .evidence()
                .entries()
                .iter()
                .filter_map(|entry| entry.occurrence())
                .all(|occurrence| matches!(
                    occurrence.shape(),
                    Some(DefinitionShape::Systemd {
                        schedule: ShapeState::Known(_),
                        target: ShapeState::Known(_),
                        command: ShapeState::Unknown(ShapeUnknownReason::Incomplete),
                        ..
                    })
                ))
        );
        let input = crate::diagnostic::DiagnosticInput::new(
            crate::evidence::TargetPlatform::Linux,
            crate::evidence::ScanScope::System,
            crate::evidence::ScanWindow::new(std::time::UNIX_EPOCH, Duration::from_secs(1))
                .unwrap(),
            report.evidence().clone(),
        )
        .unwrap();
        let gc_report = crate::diagnostic::diagnose(input);
        let claims = gc_report.automations()[0].claims();
        assert!(matches!(
            claims
                .configuration()
                .provenance()
                .authority(AuthorityRole::AutomationMapping),
            AuthorityResolution::Resolved(_)
        ));
    }

    #[test]
    fn readable_unsupported_command_keeps_structural_candidate() {
        let target = SystemdUnitId::new(NIX_GC_SERVICE).unwrap();
        let properties = SystemdTimerProperties::new(
            target,
            vec![SystemdTrigger::OnCalendar("03:15:00".to_owned())],
            SystemdTimerPolicy::new(None, None, false, None, false, false, false),
        )
        .unwrap();
        let snapshot = SystemdBusSnapshot::new(
            SystemdManagerIdentity::System,
            Subject::System,
            SystemdUnitId::new(NIX_GC_TIMER).unwrap(),
            SourceRootId::new(2),
            CaptureSequence::new(1),
            Presence::Present,
            Presence::Present,
            1,
            1,
            Ok(Some(properties)),
        )
        .unwrap()
        .with_command(Ok(Some(SystemdCommandIdentity::unknown(
            SystemdCommandUnknownReason::WrapperMismatch,
        ))));
        let normalized =
            normalize_systemd_snapshot(snapshot, "e8d924d50a462f89166e31a27bdcbbade35fd8e6")
                .unwrap();
        assert!(
            normalized
                .evidence()
                .entries()
                .iter()
                .all(|entry| entry.occurrence().is_some())
        );
        assert!(normalized.evidence().entries().iter().any(|entry| {
            entry.component() == ObservationComponent::Command
                && entry.presence()
                    == Presence::Unknown(ObservationUnknownReason::UnsupportedSyntax)
        }));
        assert!(normalized.evidence().entries().iter().any(|entry| {
            entry.component() == ObservationComponent::Schedule
                && entry.presence() == Presence::Present
        }));
        assert!(matches!(
            normalized.authority(),
            AuthorityResolution::Resolved(_)
        ));
    }

    #[test]
    fn permission_denied_configuration_and_runtime_reach_report_claims() {
        // LLM contract: an AccessDenied transport result is normalized as
        // typed Unavailable, then local Unknown claims; it never becomes
        // Absent, erases the structural candidate, or marks the scan global.
        let target = SystemdUnitId::new(NIX_GC_SERVICE).unwrap();
        let properties = SystemdTimerProperties::new(
            target,
            vec![SystemdTrigger::OnCalendar("03:15:00".to_owned())],
            SystemdTimerPolicy::new(None, None, false, None, false, false, false),
        )
        .unwrap();
        let path = format!("/nix/store/{STORE_HASH}-unit-script-nix-gc-start/bin/nix-gc-start");
        let exec = SystemdExecStart::from_read_signature(&path, std::slice::from_ref(&path), false)
            .unwrap();
        let command = classify_nix_gc_command(
            &exec,
            Ok(format!(
                "#!/nix/store/{STORE_HASH}-bash-5/bin/bash\nset -e\n\nexec /nix/store/{STORE_HASH}-nix-2.0/bin/nix-collect-garbage --delete-old\n"
            )
            .as_bytes()),
        );
        let denied = Presence::Unavailable(UnavailableReason::PermissionDenied);
        let snapshot = SystemdBusSnapshot::new(
            SystemdManagerIdentity::System,
            Subject::System,
            SystemdUnitId::new(NIX_GC_TIMER).unwrap(),
            SourceRootId::new(1),
            CaptureSequence::new(1),
            denied,
            denied,
            1,
            1,
            Ok(Some(properties)),
        )
        .unwrap()
        .with_command(Ok(Some(command)))
        .with_authority_identity(Some(
            SystemdAuthorityIdentity::from_pins(
                "261",
                FIXTURE_REVISION,
                PACKAGE_DIGEST,
                PATCH_DIGEST,
            )
            .unwrap(),
        ));
        let normalized =
            normalize_systemd_snapshot(snapshot, "e8d924d50a462f89166e31a27bdcbbade35fd8e6")
                .unwrap();
        let input = crate::diagnostic::DiagnosticInput::new(
            crate::evidence::TargetPlatform::Linux,
            crate::evidence::ScanScope::System,
            crate::evidence::ScanWindow::new(std::time::UNIX_EPOCH, Duration::from_secs(1))
                .unwrap(),
            normalized.evidence().clone(),
        )
        .unwrap();
        let report = crate::diagnostic::diagnose(input);
        assert_eq!(report.automations().len(), 1);
        let claims = report.automations()[0].claims();
        assert!(matches!(
            claims.configuration().conclusion(),
            crate::diagnostic::Conclusion::Unknown(
                crate::diagnostic::UnknownReason::EvidenceUnavailable(
                    UnavailableReason::PermissionDenied
                )
            )
        ));
        assert!(matches!(
            claims.runtime().conclusion(),
            crate::diagnostic::Conclusion::Unknown(
                crate::diagnostic::UnknownReason::EvidenceUnavailable(
                    UnavailableReason::PermissionDenied
                )
            )
        ));
        assert_eq!(
            report.coverage().aggregate(),
            crate::report::CoverageAggregate::Partial
        );
    }

    #[test]
    fn authority_identity_requires_all_fixture_pins() {
        let exact = SystemdAuthorityIdentity::from_pins(
            "261",
            FIXTURE_REVISION,
            PACKAGE_DIGEST,
            PATCH_DIGEST,
        );
        assert!(exact.is_ok());
        assert_eq!(
            SystemdAuthorityIdentity::from_pins(
                "262",
                FIXTURE_REVISION,
                PACKAGE_DIGEST,
                PATCH_DIGEST
            ),
            Err(SystemdAuthorityUnknownReason::VersionUnknown)
        );
        assert_eq!(
            SystemdAuthorityIdentity::from_pins("261", FIXTURE_REVISION, "wrong", PATCH_DIGEST),
            Err(SystemdAuthorityUnknownReason::PackageUnknown)
        );
        assert_eq!(
            SystemdAuthorityIdentity::from_pins("261", "wrong", PACKAGE_DIGEST, PATCH_DIGEST),
            Err(SystemdAuthorityUnknownReason::NixpkgsUnknown)
        );
        assert_eq!(
            SystemdAuthorityIdentity::from_pins("261", FIXTURE_REVISION, PACKAGE_DIGEST, "wrong"),
            Err(SystemdAuthorityUnknownReason::PatchSetUnknown)
        );
    }

    #[test]
    fn unresolved_subjects_are_rejected_at_the_systemd_boundary() {
        let subject =
            Subject::Unresolved(crate::evidence::SubjectOrdinal::new(1).expect("nonzero ordinal"));
        let result = SystemdBusSnapshot::new(
            SystemdManagerIdentity::User,
            subject,
            SystemdUnitId::new(NIX_GC_TIMER).unwrap(),
            SourceRootId::new(7),
            CaptureSequence::new(1),
            Presence::Present,
            Presence::Absent,
            0,
            0,
            Ok(None),
        );
        assert_eq!(result, Err(InputError::InvalidSubject));
    }

    #[test]
    fn missing_generation_keeps_structural_candidate_and_schedule_unknown() {
        let target = SystemdUnitId::new(NIX_GC_SERVICE).unwrap();
        let properties = SystemdTimerProperties::new(
            target,
            vec![SystemdTrigger::OnCalendar("03:15:00".to_owned())],
            SystemdTimerPolicy::new(None, None, false, None, false, false, false),
        )
        .unwrap();
        let path = format!("/nix/store/{STORE_HASH}-unit-script-nix-gc-start/bin/nix-gc-start");
        let exec = SystemdExecStart::from_read_signature(&path, std::slice::from_ref(&path), false)
            .unwrap();
        let command = classify_nix_gc_command(
            &exec,
            Ok(format!(
                "#!/nix/store/{STORE_HASH}-bash-5/bin/bash\nset -e\n\nexec /nix/store/{STORE_HASH}-nix-2.0/bin/nix-collect-garbage --delete-old\n"
            ).as_bytes()),
        );
        let snapshot = SystemdBusSnapshot::without_generation(
            SystemdManagerIdentity::System,
            Subject::System,
            SystemdUnitId::new(NIX_GC_TIMER).unwrap(),
            SourceRootId::new(7),
            CaptureSequence::new(1),
            Presence::Present,
            Presence::Present,
            Ok(Some(properties.clone())),
        )
        .unwrap()
        .with_command(Ok(Some(command)));
        let report =
            normalize_systemd_snapshot(snapshot, "0000000000000000000000000000000000000000")
                .unwrap();
        assert!(
            report
                .evidence()
                .entries()
                .iter()
                .all(|entry| entry.occurrence().is_some())
        );
        assert!(report.evidence().entries().iter().any(|entry| {
            entry.component() == ObservationComponent::Schedule
                && entry.presence()
                    == Presence::Unavailable(UnavailableReason::ConsistencyNotAttested)
        }));
        assert!(
            report
                .evidence()
                .entries()
                .iter()
                .filter_map(|entry| entry.occurrence())
                .all(|occurrence| matches!(
                    occurrence.shape(),
                    Some(DefinitionShape::Systemd {
                        schedule: ShapeState::Unavailable(
                            UnavailableReason::ConsistencyNotAttested
                        ),
                        target: ShapeState::Unavailable(UnavailableReason::ConsistencyNotAttested),
                        ..
                    })
                ))
        );
        let input = crate::diagnostic::DiagnosticInput::new(
            crate::evidence::TargetPlatform::Linux,
            crate::evidence::ScanScope::System,
            crate::evidence::ScanWindow::new(std::time::UNIX_EPOCH, Duration::from_secs(1))
                .unwrap(),
            report.evidence().clone(),
        )
        .unwrap();
        let gc_report = crate::diagnostic::diagnose(input);
        let claims = gc_report.automations()[0].claims();
        assert!(matches!(
            claims
                .configuration()
                .provenance()
                .authority(AuthorityRole::AutomationMapping),
            AuthorityResolution::Unresolved(_)
        ));
        assert!(matches!(
            claims.schedule().conclusion(),
            crate::diagnostic::Conclusion::Unknown(
                crate::diagnostic::UnknownReason::EvidenceUnavailable(
                    UnavailableReason::ConsistencyNotAttested
                )
            )
        ));
        assert!(matches!(
            claims.consistency().conclusion(),
            crate::diagnostic::Conclusion::Unknown(
                crate::diagnostic::UnknownReason::EvidenceUnavailable(
                    UnavailableReason::ConsistencyNotAttested
                )
            )
        ));
        assert!(matches!(
            claims.command().conclusion(),
            crate::diagnostic::Conclusion::Known(crate::report::ObservationValue::Present)
        ));

        let changed = SystemdBusSnapshot::new(
            SystemdManagerIdentity::System,
            Subject::System,
            SystemdUnitId::new(NIX_GC_TIMER).unwrap(),
            SourceRootId::new(7),
            CaptureSequence::new(1),
            Presence::Present,
            Presence::Present,
            1,
            2,
            Ok(Some(properties)),
        )
        .unwrap()
        .with_command(Ok(Some(command)));
        let changed =
            normalize_systemd_snapshot(changed, "0000000000000000000000000000000000000000")
                .unwrap();
        assert!(
            changed
                .evidence()
                .entries()
                .iter()
                .all(|entry| entry.occurrence().is_some())
        );
        let changed_input = crate::diagnostic::DiagnosticInput::new(
            crate::evidence::TargetPlatform::Linux,
            crate::evidence::ScanScope::System,
            crate::evidence::ScanWindow::new(std::time::UNIX_EPOCH, Duration::from_secs(1))
                .unwrap(),
            changed.evidence().clone(),
        )
        .unwrap();
        let changed_report = crate::diagnostic::diagnose(changed_input);
        let changed_claims = changed_report.automations()[0].claims();
        assert!(matches!(
            changed_claims.configuration().conclusion(),
            crate::diagnostic::Conclusion::Unknown(
                crate::diagnostic::UnknownReason::EvidenceUnavailable(
                    UnavailableReason::ChangedDuringRead
                )
            )
        ));
        assert!(matches!(
            changed_claims.runtime().conclusion(),
            crate::diagnostic::Conclusion::Unknown(
                crate::diagnostic::UnknownReason::EvidenceUnavailable(
                    UnavailableReason::ChangedDuringRead
                )
            )
        ));
        assert!(matches!(
            changed_claims.consistency().conclusion(),
            crate::diagnostic::Conclusion::Unknown(
                crate::diagnostic::UnknownReason::EvidenceUnavailable(
                    UnavailableReason::ChangedDuringRead
                )
            )
        ));
        assert!(matches!(
            changed_claims
                .configuration()
                .provenance()
                .authority(AuthorityRole::AutomationMapping),
            AuthorityResolution::Unresolved(_)
        ));
    }
}
