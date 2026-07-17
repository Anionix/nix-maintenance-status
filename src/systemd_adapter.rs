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
        })
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
        SystemdUnitId::new("nix-gc.service").expect("catalogued Nix service identity is valid");
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
