use std::fmt;
use std::time::Duration;

use crate::catalog::{
    AuthorityResolution, AuthorityRole, AuthorityUnknownReason, CatalogScope,
    ObservedAuthorityIdentity, ProviderCatalog,
};
use crate::evidence::{
    CaptureSequence, DefinitionOccurrence, InputError, ObservationComponent, Presence, Provider,
    ProviderEvidence, ProviderEvidenceSet, ProviderLogicalKey, SourceOccurrenceKey, SourceRoot,
    SourceRootId, Subject, SystemdManagerIdentity, SystemdUnitId, UnavailableReason,
};
use crate::report::{Schedule, SystemdSchedule, SystemdTimerPolicy, SystemdTrigger};

pub const NIX_GC_TIMER: &str = "nix-gc.timer";
pub const NIX_GC_SERVICE: &str = "nix-gc.service";

const NIXOS_FIXTURE_REVISION: &str = "6cdc7fc76e8bf7fde9fa43a849fcaaa70e230dee";
const SYSTEMD_PACKAGE_DIGEST: &str =
    "e8807564442a4348a6a7006109a2d900480c56454553ad490d5946a2dc4dcc64";
const NIXPKGS_PATCH_DIGEST: &str =
    "16689e241f3f394bcdc5b91ba22efe2067c8b925d8de717f859426f240f4af9d";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SystemdCommandUnknownReason {
    MalformedExecStart,
    WrapperUnavailable,
    WrapperMismatch,
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
pub struct SystemdAuthorityIdentity(());

impl SystemdAuthorityIdentity {
    pub fn from_pins(
        systemd_version: &str,
        nixpkgs_revision: &str,
        package_digest: &str,
        patch_digest: &str,
    ) -> Result<Self, SystemdAuthorityUnknownReason> {
        if systemd_version != "261" {
            return Err(SystemdAuthorityUnknownReason::VersionUnknown);
        }
        if nixpkgs_revision != NIXOS_FIXTURE_REVISION {
            return Err(SystemdAuthorityUnknownReason::NixpkgsUnknown);
        }
        if package_digest != SYSTEMD_PACKAGE_DIGEST {
            return Err(SystemdAuthorityUnknownReason::PackageUnknown);
        }
        if patch_digest != NIXPKGS_PATCH_DIGEST {
            return Err(SystemdAuthorityUnknownReason::PatchSetUnknown);
        }
        Ok(Self(()))
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
    pub fn from_read_signature(
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

    fn is_generated_wrapper(&self) -> bool {
        safe_store_path(&self.executable)
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
enum CommandIdentityKind {
    NixCollectGarbage,
    Unknown(SystemdCommandUnknownReason),
}

impl SystemdCommandIdentity {
    pub(crate) const fn unknown(reason: SystemdCommandUnknownReason) -> Self {
        Self(CommandIdentityKind::Unknown(reason))
    }

    pub const fn is_exact(self) -> bool {
        matches!(self.0, CommandIdentityKind::NixCollectGarbage)
    }

    // LLM contract: Exact is Present; every non-exact identity is Unknown and
    // maps only to unavailable evidence, never to Absent.
    pub const fn presence(self) -> Presence {
        match self {
            Self(CommandIdentityKind::NixCollectGarbage) => Presence::Present,
            Self(CommandIdentityKind::Unknown(_)) => {
                Presence::Unavailable(UnavailableReason::MalformedEvidence)
            }
        }
    }
}

// LLM contract: one generated wrapper plus one safe `exec` command is exact;
// overrides, shell syntax, malformed bytes, and unavailable wrappers remain
// Unknown. Raw command text never crosses the evidence boundary.
pub fn classify_nix_gc_command(
    exec_start: &SystemdExecStart,
    wrapper: Result<&[u8], SystemdBusError>,
) -> SystemdCommandIdentity {
    if !exec_start.is_generated_wrapper() {
        return SystemdCommandIdentity::unknown(SystemdCommandUnknownReason::OverrideDetected);
    }
    let bytes = match wrapper {
        Ok(bytes) => bytes,
        Err(_) => {
            return SystemdCommandIdentity::unknown(
                SystemdCommandUnknownReason::WrapperUnavailable,
            );
        }
    };
    let script = match std::str::from_utf8(bytes) {
        Ok(script) => script.strip_suffix('\n').unwrap_or(script),
        Err(_) => return SystemdCommandIdentity::unknown(SystemdCommandUnknownReason::NonUtf8),
    };
    if script.is_empty() || script.ends_with('\n') || script.contains('\r') {
        return SystemdCommandIdentity::unknown(SystemdCommandUnknownReason::WrapperMismatch);
    }
    let lines: Vec<_> = script.lines().collect();
    let command_line = match lines.as_slice() {
        [shebang, command] if shebang.starts_with("#!/") => *command,
        [shebang, strict, blank, command]
            if shebang.starts_with("#!/") && *strict == "set -e" && blank.is_empty() =>
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
    if !safe_store_path(command) || !command.ends_with("/bin/nix-collect-garbage") {
        return SystemdCommandIdentity::unknown(SystemdCommandUnknownReason::WrapperMismatch);
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
        if needs_value && options.next().is_none_or(|value| !safe_gc_value(value)) {
            return SystemdCommandIdentity::unknown(SystemdCommandUnknownReason::AmbiguousShell);
        }
    }
    SystemdCommandIdentity(CommandIdentityKind::NixCollectGarbage)
}

fn safe_gc_option(value: &str) -> bool {
    !value.is_empty()
        && value.starts_with('-')
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/' | b'=' | b'_' | b'+' | b'-')
        })
}

fn safe_store_path(value: &str) -> bool {
    let mut parts = value.split('/');
    matches!(parts.next(), Some(""))
        && matches!(parts.next(), Some("nix"))
        && matches!(parts.next(), Some("store"))
        && parts.all(|part| !part.is_empty() && part != "..")
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'+' | b'-')
        })
}

fn safe_gc_value(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/' | b'=' | b'_' | b'+' | b'-')
        })
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
    pub fn with_command(
        mut self,
        command: Result<Option<SystemdCommandIdentity>, SystemdBusError>,
    ) -> Self {
        self.command = command;
        self
    }

    pub fn with_authority_identity(mut self, identity: Option<SystemdAuthorityIdentity>) -> Self {
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

// LLM contract: normalization is triggered by one typed, bounded snapshot.
// A catalogued system nix-gc.timer plus nix-gc.service target is the only
// condition that creates an occurrence; unknown/user/foreign identities retain
// identity-free evidence. Generation changes become local Unavailable evidence.
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
    let is_mapping = matches!(
        observed_authority,
        AuthorityResolution::Resolved(reference)
            if reference.entry_id().as_str() == "nixos.gc.mapping.v1"
                && reference.role() == AuthorityRole::AutomationMapping
                && reference.scope() == CatalogScope::Provider(Provider::NixOsSystemd)
    );
    let expected_timer =
        SystemdUnitId::new(NIX_GC_TIMER).expect("catalogued Nix timer identity is valid");
    let expected_service =
        SystemdUnitId::new(NIX_GC_SERVICE).expect("catalogued Nix service identity is valid");
    let changed = snapshot.generation_changed();
    let generation_attested = snapshot.generation_attested();
    let unstable = changed || !generation_attested;
    let has_gc_identity = snapshot.manager == SystemdManagerIdentity::System
        && generation_attested
        && snapshot.unit == expected_timer
        && matches!(
            snapshot.properties.as_ref(),
            Ok(Some(properties)) if properties.target() == &expected_service
        )
        && matches!(
            snapshot.command,
            Ok(Some(command)) if command.is_exact()
        )
        && snapshot.authority_identity.is_some()
        && matches!(operation_authority, AuthorityResolution::Resolved(_))
        && is_mapping;
    let occurrence = (!unstable && has_gc_identity).then(|| occurrence(&snapshot));
    let authority = if has_gc_identity {
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
        )?,
        make_evidence(
            ObservationComponent::Runtime,
            runtime,
            snapshot.subject,
            occurrence.as_ref(),
        )?,
    ];
    if snapshot.manager == SystemdManagerIdentity::System {
        let command_presence = match snapshot.command {
            Ok(Some(command)) => command.presence(),
            Ok(None) => Presence::Unavailable(UnavailableReason::MalformedEvidence),
            Err(error) => error.presence(),
        };
        entries.push(make_evidence(
            ObservationComponent::Command,
            command_presence,
            snapshot.subject,
            occurrence.as_ref(),
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
    component: ObservationComponent,
    presence: Presence,
    subject: Subject,
    occurrence: Option<&DefinitionOccurrence>,
) -> Result<ProviderEvidence, SystemdAdapterError> {
    occurrence.map_or_else(
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
    )
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

    fn generated_exec() -> SystemdExecStart {
        let path = "/nix/store/abc-unit-script-nix-gc-start/bin/nix-gc-start".to_owned();
        SystemdExecStart::from_read_signature(&path, std::slice::from_ref(&path), false).unwrap()
    }

    #[test]
    fn generated_wrapper_is_the_only_exact_command_identity() {
        let exec = generated_exec();
        assert!(classify_nix_gc_command(
            &exec,
            Ok(b"#!/bin/sh\nset -e\n\nexec /nix/store/nix/bin/nix-collect-garbage --delete-old\n"),
        ).is_exact());
        assert!(
            !classify_nix_gc_command(
                &exec,
                Ok(b"#!/bin/sh\nset -e\n\nexec /bin/sh -c nix-collect-garbage\n"),
            )
            .is_exact()
        );
        assert!(
            !classify_nix_gc_command(
                &exec,
                Ok(b"#!/bin/sh\nset -e\n\nexec /nix/store/nix/bin/nix-collect-garbage $(secret)\n"),
            )
            .is_exact()
        );
    }

    #[test]
    fn malformed_or_unavailable_wrappers_never_leak_raw_data() {
        let exec = generated_exec();
        assert!(!classify_nix_gc_command(&exec, Ok(&[0xffu8][..])).is_exact());
        assert!(!classify_nix_gc_command(&exec, Err(SystemdBusError::OperationFailed)).is_exact());
        assert!(!format!("{exec:?}").contains("nix-gc-start"));
    }

    #[test]
    fn authority_identity_requires_all_fixture_pins() {
        let exact = SystemdAuthorityIdentity::from_pins(
            "261",
            NIXOS_FIXTURE_REVISION,
            SYSTEMD_PACKAGE_DIGEST,
            NIXPKGS_PATCH_DIGEST,
        );
        assert!(exact.is_ok());
        assert_eq!(
            SystemdAuthorityIdentity::from_pins(
                "262",
                NIXOS_FIXTURE_REVISION,
                SYSTEMD_PACKAGE_DIGEST,
                NIXPKGS_PATCH_DIGEST
            ),
            Err(SystemdAuthorityUnknownReason::VersionUnknown)
        );
        assert_eq!(
            SystemdAuthorityIdentity::from_pins(
                "261",
                NIXOS_FIXTURE_REVISION,
                "wrong",
                NIXPKGS_PATCH_DIGEST
            ),
            Err(SystemdAuthorityUnknownReason::PackageUnknown)
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
    fn missing_generation_keeps_systemd_identity_and_schedule_unknown() {
        let snapshot = SystemdBusSnapshot::without_generation(
            SystemdManagerIdentity::System,
            Subject::System,
            SystemdUnitId::new(NIX_GC_TIMER).unwrap(),
            SourceRootId::new(7),
            CaptureSequence::new(1),
            Presence::Present,
            Presence::Present,
            Ok(None),
        )
        .unwrap();
        let report =
            normalize_systemd_snapshot(snapshot, "e8d924d50a462f89166e31a27bdcbbade35fd8e6")
                .unwrap();
        assert!(
            report
                .evidence()
                .entries()
                .iter()
                .all(|entry| entry.occurrence().is_none())
        );
        assert!(report.evidence().entries().iter().any(|entry| {
            entry.component() == ObservationComponent::Schedule
                && entry.presence()
                    == Presence::Unavailable(UnavailableReason::ConsistencyNotAttested)
        }));
    }
}
