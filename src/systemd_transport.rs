use crate::evidence::{InputError, Subject, SystemdManagerIdentity};
use crate::systemd_adapter::SystemdBusError;

#[cfg(target_os = "linux")]
use crate::evidence::{CaptureSequence, Presence, SourceRootId};
#[cfg(target_os = "linux")]
use crate::systemd_adapter::{
    NIX_GC_SERVICE, NIX_GC_TIMER, SystemdBusSnapshot, SystemdCommandIdentity, SystemdExecStart,
    SystemdTimerProperties, classify_nix_gc_command, normalize_nix_gc_state,
};

pub const SYSTEMD_DESTINATION: &str = "org.freedesktop.systemd1";
pub const SYSTEMD_MANAGER_PATH: &str = "/org/freedesktop/systemd1";
pub const SYSTEMD_MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
pub const SYSTEMD_PROPERTIES_INTERFACE: &str = "org.freedesktop.DBus.Properties";
pub const SYSTEMD_TIMER_INTERFACE: &str = "org.freedesktop.systemd1.Timer";

/// The transport accepts only the system bus or a validated current-user bus.
/// It never consults session-bus environment variables or enumerates users.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemdBusScope {
    System,
    CurrentUser(CurrentUserUid),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurrentUserUid(u32);

impl SystemdBusScope {
    pub const fn manager(self) -> SystemdManagerIdentity {
        match self {
            Self::System => SystemdManagerIdentity::System,
            Self::CurrentUser(_) => SystemdManagerIdentity::User,
        }
    }

    pub const fn subject(self) -> Subject {
        match self {
            Self::System => Subject::System,
            Self::CurrentUser(CurrentUserUid(uid)) => Subject::Uid(uid),
        }
    }

    /// Create the only user-bus scope exposed to callers: the current
    /// process UID. A caller cannot select another user's bus by construction.
    #[cfg(target_os = "linux")]
    pub fn current_user(uid: u32) -> Result<Self, SystemdTransportError> {
        // SAFETY: geteuid has no preconditions and only reads process identity.
        let process_uid = unsafe { libc::geteuid() };
        if uid != process_uid {
            return Err(SystemdTransportError::InvalidInput(
                InputError::InvalidSubject,
            ));
        }
        Ok(Self::CurrentUser(CurrentUserUid(uid)))
    }

    pub fn unix_address(self) -> String {
        match self {
            Self::System => "unix:path=/run/dbus/system_bus_socket".to_owned(),
            Self::CurrentUser(CurrentUserUid(uid)) => format!("unix:path=/run/user/{uid}/bus"),
        }
    }
}

pub const READ_ONLY_METHODS: &[&str] = &[
    "ListUnitFilesByPatterns",
    "ListUnitsByNames",
    "GetUnit",
    "GetAll",
];

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
enum ReadOnlyMethod {
    ListUnitFilesByPatterns,
    ListUnitsByNames,
    GetUnit,
    GetAll,
}

#[cfg(target_os = "linux")]
impl ReadOnlyMethod {
    const fn name(self) -> &'static str {
        match self {
            Self::ListUnitFilesByPatterns => "ListUnitFilesByPatterns",
            Self::ListUnitsByNames => "ListUnitsByNames",
            Self::GetUnit => "GetUnit",
            Self::GetAll => "GetAll",
        }
    }
}

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
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;

    use zbus::blocking::Connection;
    use zbus::zvariant::{OwnedObjectPath, OwnedValue};

    use super::*;
    use crate::report::{SystemdTimerPolicy, SystemdTrigger};

    const MAX_REPLY_BYTES: usize = 1_048_576;
    const MAX_ROWS: usize = 128;
    // systemd v261 exposes a larger read-only property map for Service units
    // than for list rows; keep the map bounded without rejecting the official
    // NixOS service solely because optional properties were added.
    const MAX_PROPERTY_ROWS: usize = 512;
    const MAX_TIMER_ENTRIES: usize = 128;

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
        // is not advertised as an atomic consistency proof. The transport
        // does not invent NixOS package/patch authority when those pins are
        // not locally observed; the snapshot remains identity-free.
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
            let expected_service = crate::evidence::SystemdUnitId::new(NIX_GC_SERVICE)
                .map_err(SystemdTransportError::InvalidInput)?;
            let command = match &properties {
                Ok(Some(properties)) if properties.target() == &expected_service => self
                    .unit_path(NIX_GC_SERVICE)
                    .and_then(|path| self.service_command(&path))
                    .map(Some),
                Ok(Some(_)) => Ok(Some(SystemdCommandIdentity::unknown(
                    crate::systemd_adapter::SystemdCommandUnknownReason::OverrideDetected,
                ))),
                Ok(None) => Ok(None),
                Err(error) => Err(*error),
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
            .map(|snapshot| snapshot.with_command(command))
            .map_err(SystemdTransportError::InvalidInput)
        }

        fn configured(&self) -> Presence {
            match self.call::<_, Vec<(String, String)>>(
                SYSTEMD_MANAGER_PATH,
                SYSTEMD_MANAGER_INTERFACE,
                ReadOnlyMethod::ListUnitFilesByPatterns,
                &(Vec::<&str>::new(), vec![NIX_GC_TIMER]),
            ) {
                Ok(files) => normalize_nix_gc_state(exact_row_presence(&files, |(name, _)| {
                    name == NIX_GC_TIMER
                })),
                Err(error) => normalize_nix_gc_state(Err(error)),
            }
        }

        fn loaded(&self) -> Presence {
            match self.call::<_, Vec<UnitRow>>(
                SYSTEMD_MANAGER_PATH,
                SYSTEMD_MANAGER_INTERFACE,
                ReadOnlyMethod::ListUnitsByNames,
                &(vec![NIX_GC_TIMER],),
            ) {
                Ok(units) => normalize_nix_gc_state(exact_row_presence(&units, |unit| {
                    unit.0 == NIX_GC_TIMER
                })),
                Err(error) => normalize_nix_gc_state(Err(error)),
            }
        }

        fn unit_path(&self, unit: &str) -> Result<OwnedObjectPath, SystemdBusError> {
            self.call(
                SYSTEMD_MANAGER_PATH,
                SYSTEMD_MANAGER_INTERFACE,
                ReadOnlyMethod::GetUnit,
                &(unit,),
            )
        }

        fn timer_properties(
            &self,
            path: &OwnedObjectPath,
        ) -> Result<SystemdTimerProperties, SystemdBusError> {
            let values = self.properties(path, SYSTEMD_TIMER_INTERFACE)?;
            // LLM contract: pinned Timer fields normalize into typed triggers
            // and policy; unknown bases, malformed variants, and oversized
            // collections stay unavailable without exposing raw D-Bus data.
            let target = value::<String>(&values, "Unit")
                .and_then(|value| {
                    crate::evidence::SystemdUnitId::new(&value)
                        .map_err(|_| SystemdBusError::InvalidSignature)
                })
                .map_err(|_| SystemdBusError::InvalidSignature)?;
            let mut triggers = Vec::new();
            let monotonic = value::<Vec<(String, u64, u64)>>(&values, "TimersMonotonic")?;
            if monotonic.len() > MAX_TIMER_ENTRIES {
                return Err(SystemdBusError::ResourceLimitExceeded);
            }
            for (name, usec, _) in monotonic {
                triggers.push(monotonic_trigger(&name, usec)?);
            }
            let calendar = value::<Vec<(String, String, u64)>>(&values, "TimersCalendar")?;
            if calendar.len() > MAX_TIMER_ENTRIES {
                return Err(SystemdBusError::ResourceLimitExceeded);
            }
            for (base, expression, _) in calendar {
                if base != "OnCalendar" {
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

        fn service_command(
            &self,
            path: &OwnedObjectPath,
        ) -> Result<SystemdCommandIdentity, SystemdBusError> {
            let unit_values = self.properties(path, "org.freedesktop.systemd1.Unit")?;
            if !effective_unit(&unit_values)? {
                return Ok(SystemdCommandIdentity::unknown(
                    crate::systemd_adapter::SystemdCommandUnknownReason::OverrideDetected,
                ));
            }
            let values = self.properties(path, "org.freedesktop.systemd1.Service")?;
            let rows = value::<Vec<ServiceExecStartRow>>(&values, "ExecStart")?;
            let exec_start = normalize_service_exec_start(rows)?;
            let wrapper = read_wrapper(exec_start.executable());
            let wrapper = wrapper
                .as_ref()
                .map(|bytes| bytes.as_slice())
                .map_err(|error| *error);
            Ok(classify_nix_gc_command(&exec_start, wrapper))
        }

        fn properties(
            &self,
            path: &OwnedObjectPath,
            interface: &str,
        ) -> Result<HashMap<String, OwnedValue>, SystemdBusError> {
            // LLM contract: GetAll is read-only and its map is bounded before
            // any named value is normalized; raw variants do not escape.
            self.properties_path(path.as_str(), interface)
        }

        fn properties_path(
            &self,
            path: &str,
            interface: &str,
        ) -> Result<HashMap<String, OwnedValue>, SystemdBusError> {
            let values: HashMap<String, OwnedValue> = self.call(
                path,
                SYSTEMD_PROPERTIES_INTERFACE,
                ReadOnlyMethod::GetAll,
                &(interface,),
            )?;
            if values.len() > MAX_PROPERTY_ROWS {
                Err(SystemdBusError::ResourceLimitExceeded)
            } else {
                Ok(values)
            }
        }

        // LLM contract: only ReadOnlyMethod values can reach the D-Bus call;
        // replies are byte-bounded before typed deserialization and failures
        // lose all raw payload text at the SystemdBusError boundary.
        fn call<B, T>(
            &self,
            path: &str,
            interface: &str,
            method: ReadOnlyMethod,
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
                    method.name(),
                    body,
                )
                .map_err(|error| map_zbus_error(&error))?;
            let body = reply.body();
            if body.len() > MAX_REPLY_BYTES {
                return Err(SystemdBusError::ResourceLimitExceeded);
            }
            body.deserialize()
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

    type ServiceExecStartRow = (String, Vec<String>, bool, u64, u64, u64, u64, u32, i32, i32);

    // LLM contract: exactly one typed read-signature row is required for the
    // generated service. The write signature, duplicate rows, malformed text,
    // and raw variants never cross this boundary.
    pub(super) fn normalize_service_exec_start(
        rows: Vec<ServiceExecStartRow>,
    ) -> Result<SystemdExecStart, SystemdBusError> {
        if rows.len() != 1 {
            return Err(SystemdBusError::InvalidSignature);
        }
        let (executable, argv, ignore_failure, _, _, _, _, _, _, _) = rows
            .into_iter()
            .next()
            .ok_or(SystemdBusError::InvalidSignature)?;
        SystemdExecStart::from_read_signature(&executable, &argv, ignore_failure)
            .map_err(|_| SystemdBusError::InvalidSignature)
    }

    // LLM contract: only a strict Nix store wrapper path is opened with
    // O_NOFOLLOW, then the opened fd is bounded and canonicalized before
    // reading. Symlinks, races, non-files, oversized data, and I/O errors
    // become typed Unknown; raw paths/bytes never enter the report.
    fn read_wrapper(path: &str) -> Result<Vec<u8>, SystemdBusError> {
        const MAX_WRAPPER_BYTES: u64 = 65_536;
        if !path.starts_with("/nix/store/")
            || !path.ends_with("-unit-script-nix-gc-start/bin/nix-gc-start")
            || path.split('/').any(|component| component == "..")
        {
            return Err(SystemdBusError::OperationFailed);
        }
        if !crate::systemd_adapter::is_safe_store_path(path) {
            return Err(SystemdBusError::OperationFailed);
        }
        let expected = std::fs::canonicalize(path).map_err(|_| SystemdBusError::OperationFailed)?;
        if expected != std::path::Path::new(path) {
            return Err(SystemdBusError::OperationFailed);
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| SystemdBusError::OperationFailed)?;
        let fd_path = format!("/proc/self/fd/{}", file.as_raw_fd());
        let actual =
            std::fs::canonicalize(fd_path).map_err(|_| SystemdBusError::OperationFailed)?;
        if actual != expected {
            return Err(SystemdBusError::OperationFailed);
        }
        let metadata = file
            .metadata()
            .map_err(|_| SystemdBusError::OperationFailed)?;
        if !metadata.is_file() || metadata.len() > MAX_WRAPPER_BYTES {
            return Err(SystemdBusError::ResourceLimitExceeded);
        }
        let mut bytes = Vec::new();
        file.take(MAX_WRAPPER_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| SystemdBusError::OperationFailed)?;
        if bytes.len() as u64 > MAX_WRAPPER_BYTES {
            return Err(SystemdBusError::ResourceLimitExceeded);
        }
        Ok(bytes)
    }

    // LLM contract: only a canonical NixOS nix-gc.service fragment with an
    // empty, well-formed DropInPaths list is effective. A replacement,
    // malformed path, or override remains Unknown; raw paths do not escape.
    fn effective_unit(values: &HashMap<String, OwnedValue>) -> Result<bool, SystemdBusError> {
        let fragment = value::<String>(values, "FragmentPath")?;
        let dropins = value::<Vec<String>>(values, "DropInPaths")?;
        if fragment.chars().any(char::is_control) || !is_generated_fragment(&fragment) {
            return Ok(false);
        }
        if dropins.iter().any(|path| {
            path.is_empty() || path.chars().any(char::is_control) || !path.starts_with('/')
        }) {
            return Err(SystemdBusError::InvalidSignature);
        }
        Ok(dropins.is_empty())
    }

    fn is_generated_fragment(path: &str) -> bool {
        if path == "/etc/systemd/system/nix-gc.service" {
            return true;
        }
        let Some(object) = path
            .strip_prefix("/nix/store/")
            .and_then(|rest| rest.split('/').next())
        else {
            return false;
        };
        crate::systemd_adapter::is_safe_store_path(path)
            && path.ends_with("/nix-gc.service")
            && object
                .split_once('-')
                .is_some_and(|(_, name)| name.starts_with("unit-") || name == "system-units")
    }

    // LLM contract: an empty exact reply is Absent, one exact row is Present,
    // and a non-empty reply without the requested identity is malformed.
    pub(super) fn exact_row_presence<T, F>(rows: &[T], matches: F) -> Result<bool, SystemdBusError>
    where
        F: Fn(&T) -> bool,
    {
        if rows.len() > MAX_ROWS {
            return Err(SystemdBusError::ResourceLimitExceeded);
        }
        if rows.is_empty() {
            Ok(false)
        } else if rows.iter().any(matches) {
            Ok(true)
        } else {
            Err(SystemdBusError::InvalidSignature)
        }
    }

    // LLM contract: only a named property with a bounded reply can become a
    // typed value; missing, malformed, or oversized values never retain raw data.
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

    // LLM contract: only the pinned systemd monotonic property names map to
    // typed triggers; unknown names remain InvalidSignature.
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

    // LLM contract: transport errors become the finite typed taxonomy only;
    // D-Bus names and descriptions never cross into report evidence.
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
            SystemdBusScope::CurrentUser(CurrentUserUid(1000)).unix_address(),
            "unix:path=/run/user/1000/bus"
        );
        assert!(
            !SystemdBusScope::CurrentUser(CurrentUserUid(1000))
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

    #[cfg(target_os = "linux")]
    #[test]
    fn exact_unit_reply_boundary_rejects_wrong_rows() {
        assert_eq!(
            linux::exact_row_presence::<String, _>(&[], |_| true),
            Ok(false)
        );
        assert_eq!(
            linux::exact_row_presence(&["other.timer"], |unit| *unit == "nix-gc.timer"),
            Err(SystemdBusError::InvalidSignature)
        );
        assert_eq!(
            linux::exact_row_presence(&["nix-gc.timer"], |unit| *unit == "nix-gc.timer"),
            Ok(true)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn service_exec_start_uses_only_the_documented_read_signature() {
        let path = "/nix/store/abc-unit-script-nix-gc-start/bin/nix-gc-start".to_owned();
        let row = (path.clone(), vec![path], false, 0, 0, 0, 0, 0, 0, 0);
        assert!(linux::normalize_service_exec_start(vec![row]).is_ok());
        assert_eq!(
            linux::normalize_service_exec_start(Vec::new()),
            Err(SystemdBusError::InvalidSignature)
        );
    }
}
