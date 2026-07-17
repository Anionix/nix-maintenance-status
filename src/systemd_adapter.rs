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
    ServiceUnknown,
    NameHasNoOwner,
    NoSuchUnit,
    NoReply,
    InvalidSignature,
    UnknownMethod,
    OperationFailed,
}

impl SystemdBusError {
    pub const fn presence(self) -> Presence {
        match self {
            Self::NoSuchUnit => Presence::Absent,
            Self::AccessDenied => Presence::Unavailable(UnavailableReason::PermissionDenied),
            Self::NoReply => Presence::Unavailable(UnavailableReason::TimedOut),
            Self::InvalidSignature | Self::UnknownMethod => {
                Presence::Unavailable(UnavailableReason::MalformedEvidence)
            }
            Self::ServiceUnknown | Self::NameHasNoOwner => {
                Presence::Unavailable(UnavailableReason::InterfaceUnavailable)
            }
            Self::OperationFailed => Presence::Unavailable(UnavailableReason::OperationFailed),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdTimerProperties {
    triggers: Vec<SystemdTrigger>,
    policy: SystemdTimerPolicy,
}

impl SystemdTimerProperties {
    pub fn new(
        triggers: Vec<SystemdTrigger>,
        policy: SystemdTimerPolicy,
    ) -> Result<Self, InputError> {
        SystemdSchedule::new(triggers.clone(), policy)
            .map_err(|_| InputError::InvalidNormalizedValue)?;
        Ok(Self { triggers, policy })
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
    source: SourceRootId,
    capture: CaptureSequence,
    configured: Presence,
    loaded: Presence,
    generation_before: u64,
    generation_after: u64,
    properties: Option<SystemdTimerProperties>,
}

impl SystemdBusSnapshot {
    // The transport adapter supplies only values from ListUnitFiles/ListUnits
    // and Properties.GetAll. No D-Bus bytes, error strings, or raw XML cross
    // this constructor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        manager: SystemdManagerIdentity,
        subject: Subject,
        source: SourceRootId,
        capture: CaptureSequence,
        configured: Presence,
        loaded: Presence,
        generation_before: u64,
        generation_after: u64,
        properties: Option<SystemdTimerProperties>,
    ) -> Result<Self, InputError> {
        if (manager == SystemdManagerIdentity::System && subject != Subject::System)
            || (manager == SystemdManagerIdentity::User
                && !matches!(subject, Subject::Uid(_) | Subject::Unresolved(_)))
        {
            return Err(InputError::InvalidSubject);
        }
        Ok(Self {
            manager,
            subject,
            source,
            capture,
            configured,
            loaded,
            generation_before,
            generation_after,
            properties,
        })
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
    AuthorityUnknown(AuthorityUnknownReason),
}

pub fn normalize_bus_state(result: Result<bool, SystemdBusError>) -> Presence {
    result.map_or_else(SystemdBusError::presence, |present| {
        if present {
            Presence::Present
        } else {
            Presence::Absent
        }
    })
}

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
            canonical_timer_id: SystemdUnitId::new(NIX_GC_TIMER)
                .expect("catalogued Nix timer identity is valid"),
        },
        SourceOccurrenceKey::new(SourceRoot::SystemdUnit(snapshot.source), 1),
        snapshot.capture.clone(),
    )
}

// LLM contract: normalization is triggered by one typed, bounded snapshot.
// Matching authority and unchanged manager generation are prerequisites;
// generation changes become local Unavailable evidence. NoSuchUnit is Absent
// only for the finite nix-gc.timer identity, all other bus failures stay
// Unavailable, and no path performs I/O, retries, mutation, telemetry, or GC.
pub fn normalize_systemd_snapshot(
    snapshot: SystemdBusSnapshot,
    authority: AuthorityResolution,
) -> Result<SystemdNormalizedObservation, SystemdAdapterError> {
    let AuthorityResolution::Resolved(_) = authority else {
        return Err(SystemdAdapterError::AuthorityUnknown(match authority {
            AuthorityResolution::Unresolved(reason) => reason,
            _ => AuthorityUnknownReason::ExactBasisUnverifiable,
        }));
    };
    let occurrence = occurrence(&snapshot);
    let changed = snapshot.generation_before != snapshot.generation_after;
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
        ProviderEvidence::with_occurrence(
            Provider::NixOsSystemd,
            snapshot.subject,
            ObservationComponent::Configuration,
            configuration,
            occurrence.clone(),
        )
        .map_err(SystemdAdapterError::InvalidInput)?,
        ProviderEvidence::with_occurrence(
            Provider::NixOsSystemd,
            snapshot.subject,
            ObservationComponent::Runtime,
            runtime,
            occurrence.clone(),
        )
        .map_err(SystemdAdapterError::InvalidInput)?,
    ];
    if let (Some(properties), Presence::Present) = (snapshot.properties, runtime) {
        entries.push(
            ProviderEvidence::with_occurrence(
                Provider::NixOsSystemd,
                snapshot.subject,
                ObservationComponent::Schedule,
                Presence::Present,
                occurrence,
            )
            .and_then(|evidence| evidence.with_schedule(properties.schedule()))
            .map_err(SystemdAdapterError::InvalidInput)?,
        );
    }
    let evidence = ProviderEvidenceSet::new(entries).map_err(SystemdAdapterError::InvalidInput)?;
    Ok(SystemdNormalizedObservation {
        evidence,
        authority,
    })
}

pub const fn duration_from_usec(usec: u64) -> Option<Duration> {
    let seconds = usec / 1_000_000;
    let micros = usec % 1_000_000;
    Some(Duration::new(seconds, micros as u32 * 1_000))
}
