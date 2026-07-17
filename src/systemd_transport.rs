use crate::evidence::{InputError, Subject, SystemdManagerIdentity};
use crate::systemd_adapter::SystemdBusError;

#[cfg(target_os = "linux")]
use crate::evidence::{CaptureSequence, Presence, SourceRootId};
#[cfg(target_os = "linux")]
use crate::systemd_adapter::{
    NIX_GC_TIMER, SystemdBusSnapshot, SystemdTimerProperties, normalize_nix_gc_state,
};

pub const SYSTEMD_DESTINATION: &str = "org.freedesktop.systemd1";
pub const SYSTEMD_MANAGER_PATH: &str = "/org/freedesktop/systemd1";
pub const SYSTEMD_MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
pub const SYSTEMD_PROPERTIES_INTERFACE: &str = "org.freedesktop.DBus.Properties";
pub const SYSTEMD_TIMER_INTERFACE: &str = "org.freedesktop.systemd1.Timer";

/// The transport accepts only the system bus or one caller-supplied UID bus.
/// It never consults session-bus environment variables or enumerates users.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemdBusScope {
    System,
    CurrentUser { uid: u32 },
}

impl SystemdBusScope {
    pub const fn manager(self) -> SystemdManagerIdentity {
        match self {
            Self::System => SystemdManagerIdentity::System,
            Self::CurrentUser { .. } => SystemdManagerIdentity::User,
        }
    }

    pub const fn subject(self) -> Subject {
        match self {
            Self::System => Subject::System,
            Self::CurrentUser { uid } => Subject::Uid(uid),
        }
    }

    pub fn unix_address(self) -> String {
        match self {
            Self::System => "unix:path=/run/dbus/system_bus_socket".to_owned(),
            Self::CurrentUser { uid } => format!("unix:path=/run/user/{uid}/bus"),
        }
    }
}

pub const READ_ONLY_METHODS: &[&str] = &[
    "ListUnitFilesByPatterns",
    "ListUnitsByNames",
    "GetUnit",
    "GetAll",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SystemdTransportError {
    Bus(SystemdBusError),
    InvalidInput(InputError),
}

impl From<SystemdBusError> for SystemdTransportError {
    fn from(error: SystemdBusError) -> Self {
        Self::Bus(error)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::HashMap;

    use zbus::blocking::Connection;
    use zbus::zvariant::{OwnedObjectPath, OwnedValue};

    use super::*;
    use crate::report::{SystemdTimerPolicy, SystemdTrigger};

    #[derive(Debug, Clone)]
    pub struct SystemdBusTransport {
        scope: SystemdBusScope,
        connection: Connection,
    }

    impl SystemdBusTransport {
        // LLM contract: connect selects one fixed local Unix address; an
        // unavailable bus becomes typed Unavailable and no environment,
        // network address, retry, elevation, or telemetry is consulted.
        pub fn connect(scope: SystemdBusScope) -> Result<Self, SystemdTransportError> {
            let address: zbus::Address = scope
                .unix_address()
                .parse()
                .map_err(|_| SystemdBusError::Disconnected)?;
            let connection = zbus::blocking::connection::Builder::address(address)
                .map_err(|_| SystemdBusError::Disconnected)?
                .build()
                .map_err(|error| map_zbus_error(&error))?;
            Ok(Self { scope, connection })
        }

        pub const fn scope(&self) -> SystemdBusScope {
            self.scope
        }

        // LLM contract: one bounded sequence produces typed configured,
        // loaded, and timer-property results. Only the exact nix-gc.timer
        // lookup may become Absent; malformed or inaccessible values remain
        // Unavailable. systemd v261 has no read-generation, so this sequence
        // is not advertised as an atomic consistency proof.
        pub fn probe_nix_gc(
            &self,
            source: SourceRootId,
            capture: CaptureSequence,
        ) -> Result<SystemdBusSnapshot, SystemdTransportError> {
            let configured = self.configured();
            let loaded = self.loaded();
            let properties = if loaded == Presence::Present {
                self.unit_path(NIX_GC_TIMER)
                    .and_then(|path| self.timer_properties(&path))
                    .map(Some)
            } else {
                Ok(None)
            };
            // systemd v261 exposes no Manager.Generation property. Keep that
            // absence explicit instead of fabricating a race-free sequence.
            SystemdBusSnapshot::without_generation(
                self.scope.manager(),
                self.scope.subject(),
                crate::evidence::SystemdUnitId::new(NIX_GC_TIMER)
                    .map_err(SystemdTransportError::InvalidInput)?,
                source,
                capture,
                configured,
                loaded,
                properties,
            )
            .map_err(SystemdTransportError::InvalidInput)
        }

        fn configured(&self) -> Presence {
            match self.call::<_, Vec<(String, String)>>(
                SYSTEMD_MANAGER_PATH,
                SYSTEMD_MANAGER_INTERFACE,
                "ListUnitFilesByPatterns",
                &(Vec::<&str>::new(), vec![NIX_GC_TIMER]),
            ) {
                Ok(files) => {
                    normalize_nix_gc_state(Ok(files.iter().any(|(name, _)| name == NIX_GC_TIMER)))
                }
                Err(error) => normalize_nix_gc_state(Err(error)),
            }
        }

        fn loaded(&self) -> Presence {
            match self.call::<_, Vec<UnitRow>>(
                SYSTEMD_MANAGER_PATH,
                SYSTEMD_MANAGER_INTERFACE,
                "ListUnitsByNames",
                &(vec![NIX_GC_TIMER],),
            ) {
                Ok(units) => normalize_nix_gc_state(Ok(!units.is_empty())),
                Err(error) => normalize_nix_gc_state(Err(error)),
            }
        }

        fn unit_path(&self, unit: &str) -> Result<OwnedObjectPath, SystemdBusError> {
            self.call(
                SYSTEMD_MANAGER_PATH,
                SYSTEMD_MANAGER_INTERFACE,
                "GetUnit",
                &(unit,),
            )
        }

        fn timer_properties(
            &self,
            path: &OwnedObjectPath,
        ) -> Result<SystemdTimerProperties, SystemdBusError> {
            let values = self.properties(path, SYSTEMD_TIMER_INTERFACE)?;
            let target = value::<String>(&values, "Unit")
                .and_then(|value| {
                    crate::evidence::SystemdUnitId::new(&value)
                        .map_err(|_| SystemdBusError::InvalidSignature)
                })
                .map_err(|_| SystemdBusError::InvalidSignature)?;
            let mut triggers = Vec::new();
            for (name, usec, _) in value::<Vec<(String, u64, u64)>>(&values, "TimersMonotonic")? {
                triggers.push(monotonic_trigger(&name, usec)?);
            }
            for (expression, timezone, _) in
                value::<Vec<(String, String, u64)>>(&values, "TimersCalendar")?
            {
                if !timezone.is_empty() {
                    return Err(SystemdBusError::InvalidSignature);
                }
                triggers.push(SystemdTrigger::OnCalendar(expression));
            }
            if value::<bool>(&values, "OnClockChange")? {
                triggers.push(SystemdTrigger::OnClockChange);
            }
            if value::<bool>(&values, "OnTimezoneChange")? {
                triggers.push(SystemdTrigger::OnTimezoneChange);
            }
            let policy = SystemdTimerPolicy::new(
                Some(duration(value::<u64>(&values, "AccuracyUSec")?)),
                Some(duration(value::<u64>(&values, "RandomizedDelayUSec")?)),
                value(&values, "FixedRandomDelay")?,
                Some(duration(value::<u64>(&values, "RandomizedOffsetUSec")?)),
                value(&values, "DeferReactivation")?,
                value(&values, "Persistent")?,
                value(&values, "WakeSystem")?,
            );
            SystemdTimerProperties::new(target, triggers, policy)
                .map_err(|_| SystemdBusError::InvalidSignature)
        }

        fn properties(
            &self,
            path: &OwnedObjectPath,
            interface: &str,
        ) -> Result<HashMap<String, OwnedValue>, SystemdBusError> {
            self.call(
                path.as_str(),
                SYSTEMD_PROPERTIES_INTERFACE,
                "GetAll",
                &(interface,),
            )
        }

        fn call<B, T>(
            &self,
            path: &str,
            interface: &str,
            method: &str,
            body: &B,
        ) -> Result<T, SystemdBusError>
        where
            B: serde::Serialize + zbus::zvariant::DynamicType,
            T: serde::de::DeserializeOwned + zbus::zvariant::Type,
        {
            let reply = self
                .connection
                .call_method(
                    Some(SYSTEMD_DESTINATION),
                    path,
                    Some(interface),
                    method,
                    body,
                )
                .map_err(|error| map_zbus_error(&error))?;
            reply
                .body()
                .deserialize()
                .map_err(|_| SystemdBusError::InvalidSignature)
        }
    }

    type UnitRow = (
        String,
        String,
        String,
        String,
        String,
        String,
        OwnedObjectPath,
        u32,
        String,
        OwnedObjectPath,
    );

    fn value<T>(values: &HashMap<String, OwnedValue>, name: &str) -> Result<T, SystemdBusError>
    where
        T: TryFrom<OwnedValue>,
    {
        let value = values
            .get(name)
            .ok_or(SystemdBusError::InvalidSignature)?
            .try_clone()
            .map_err(|_| SystemdBusError::InvalidSignature)?;
        T::try_from(value).map_err(|_| SystemdBusError::InvalidSignature)
    }

    fn monotonic_trigger(name: &str, usec: u64) -> Result<SystemdTrigger, SystemdBusError> {
        let trigger = match name {
            "OnActiveUSec" => SystemdTrigger::OnActiveSec(duration(usec)),
            "OnBootUSec" => SystemdTrigger::OnBootSec(duration(usec)),
            "OnStartupUSec" => SystemdTrigger::OnStartupSec(duration(usec)),
            "OnUnitActiveUSec" => SystemdTrigger::OnUnitActiveSec(duration(usec)),
            "OnUnitInactiveUSec" => SystemdTrigger::OnUnitInactiveSec(duration(usec)),
            _ => return Err(SystemdBusError::InvalidSignature),
        };
        Ok(trigger)
    }

    const fn duration(usec: u64) -> std::time::Duration {
        crate::systemd_adapter::duration_from_usec(usec)
    }

    fn map_zbus_error(error: &zbus::Error) -> SystemdBusError {
        match error {
            zbus::Error::MethodError(name, _, _) => match name.as_str() {
                "org.freedesktop.systemd1.NoSuchUnit" => SystemdBusError::NoSuchUnit,
                "org.freedesktop.DBus.Error.AccessDenied" => SystemdBusError::AccessDenied,
                "org.freedesktop.DBus.Error.NoReply" => SystemdBusError::NoReply,
                "org.freedesktop.DBus.Error.ServiceUnknown" => SystemdBusError::ServiceUnknown,
                "org.freedesktop.DBus.Error.NameHasNoOwner" => SystemdBusError::NameHasNoOwner,
                "org.freedesktop.DBus.Error.UnknownMethod" => SystemdBusError::UnknownMethod,
                _ => SystemdBusError::OperationFailed,
            },
            zbus::Error::Variant(_)
            | zbus::Error::InvalidReply
            | zbus::Error::ExcessData
            | zbus::Error::IncorrectEndian => SystemdBusError::InvalidSignature,
            zbus::Error::InputOutput(_) | zbus::Error::Handshake(_) => {
                SystemdBusError::Disconnected
            }
            _ => SystemdBusError::OperationFailed,
        }
    }

    pub use self::SystemdBusTransport as Transport;
}

#[cfg(target_os = "linux")]
pub use linux::{SystemdBusTransport, Transport};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_use_only_fixed_unix_addresses() {
        assert_eq!(
            SystemdBusScope::System.unix_address(),
            "unix:path=/run/dbus/system_bus_socket"
        );
        assert_eq!(
            SystemdBusScope::CurrentUser { uid: 1000 }.unix_address(),
            "unix:path=/run/user/1000/bus"
        );
        assert!(
            !SystemdBusScope::CurrentUser { uid: 1000 }
                .unix_address()
                .contains("tcp:")
        );
    }

    #[test]
    fn allowlist_excludes_mutating_systemd_methods() {
        assert!(READ_ONLY_METHODS.contains(&"GetAll"));
        assert!(
            !READ_ONLY_METHODS
                .iter()
                .any(|method| method.contains("Start"))
        );
        assert!(
            !READ_ONLY_METHODS
                .iter()
                .any(|method| method.contains("Load"))
        );
        assert!(
            !READ_ONLY_METHODS
                .iter()
                .any(|method| method.contains("Enable"))
        );
    }
}
