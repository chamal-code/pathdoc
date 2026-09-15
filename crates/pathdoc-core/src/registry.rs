//! Reading the stored `PATH` values out of the registry.
//!
//! The only module in this crate that touches the registry, and it is read-only
//! throughout: no key is ever opened for write. `winreg` is used so the `unsafe`
//! required to call the Win32 registry API lives in the dependency rather than
//! here, where `unsafe_code` is forbidden at workspace level.
//!
//! The important property relied on is that `winreg` hands back the value
//! **unexpanded**. A `REG_EXPAND_SZ` holding `%SystemRoot%\system32` arrives as
//! that literal text, which is what lets the audit report the stored form and
//! the resolved form as two separate facts.

use std::io::ErrorKind;

use winreg::HKCU;
use winreg::HKLM;
use winreg::RegKey;
use winreg::enums::{KEY_READ, RegType};
use winreg::types::FromRegValue;

use crate::{AuditError, ValueKind};

/// Subkey holding the machine-wide environment block.
const MACHINE_SUBKEY: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";

/// Subkey holding the per-user environment block.
const USER_SUBKEY: &str = "Environment";

/// The value name, spelled the way Windows spells it. Registry value names are
/// case-insensitive, so `PATH` and `Path` reach the same value.
const VALUE_NAME: &str = "Path";

/// A `PATH` value exactly as one registry scope stores it.
#[derive(Debug, Clone)]
pub(crate) struct ScopeValue {
    /// The stored text, separators included and nothing expanded.
    pub(crate) text: String,
    /// Whether Windows stored it as `REG_SZ` or `REG_EXPAND_SZ`.
    pub(crate) kind: ValueKind,
}

/// Read `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`.
///
/// `Ok(None)` means the key or value is simply not there, which is a fact about
/// the machine rather than a failure.
pub(crate) fn read_machine_path() -> Result<Option<ScopeValue>, AuditError> {
    read_scope(HKLM, "HKLM", MACHINE_SUBKEY)
}

/// Read `HKCU\Environment`.
///
/// A user with no `PATH` of their own is normal, and reported as `Ok(None)`.
pub(crate) fn read_user_path() -> Result<Option<ScopeValue>, AuditError> {
    read_scope(HKCU, "HKCU", USER_SUBKEY)
}

/// Open one environment key and pull `Path` out of it, unexpanded.
fn read_scope(root: &RegKey, hive: &str, subkey: &str) -> Result<Option<ScopeValue>, AuditError> {
    let key = match root.open_subkey_with_flags(subkey, KEY_READ) {
        Ok(key) => key,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(AuditError::Registry(format!(
                "cannot open {hive}\\{subkey}: {err}"
            )));
        }
    };

    let value = match key.get_raw_value(VALUE_NAME) {
        Ok(value) => value,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(AuditError::Registry(format!(
                "cannot read {hive}\\{subkey}\\{VALUE_NAME}: {err}"
            )));
        }
    };

    let kind = match value.vtype {
        RegType::REG_SZ => ValueKind::Sz,
        RegType::REG_EXPAND_SZ => ValueKind::ExpandSz,
        ref other => {
            return Err(AuditError::Registry(format!(
                "{hive}\\{subkey}\\{VALUE_NAME} is {other:?}, expected REG_SZ or REG_EXPAND_SZ"
            )));
        }
    };

    // Decodes the UTF-16 bytes and trims the trailing NUL. It does not expand
    // environment references, which is exactly what is wanted here.
    let text = String::from_reg_value(&value).map_err(|err| {
        AuditError::Registry(format!(
            "cannot decode {hive}\\{subkey}\\{VALUE_NAME}: {err}"
        ))
    })?;

    Ok(Some(ScopeValue { text, kind }))
}
