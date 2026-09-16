//! Turning a stored registry value into something `PATH`-shaped.
//!
//! The registry work itself lives in `winenv`, which knows nothing about `PATH`.
//! All this module does is ask for the right value from the right scope and insist
//! on a value kind that makes sense for a `PATH` — which is where the boundary
//! between the two crates sits.

use winenv::Scope;

use crate::{AuditError, ValueKind};

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
    read_scope(Scope::Machine)
}

/// Read `HKCU\Environment`.
///
/// A user with no `PATH` of their own is normal, and reported as `Ok(None)`.
pub(crate) fn read_user_path() -> Result<Option<ScopeValue>, AuditError> {
    read_scope(Scope::User)
}

/// Pull `Path` out of one scope, unexpanded, and insist it is a string kind.
fn read_scope(scope: Scope) -> Result<Option<ScopeValue>, AuditError> {
    let Some(value) =
        winenv::read(scope, VALUE_NAME).map_err(|err| AuditError::Registry(err.to_string()))?
    else {
        return Ok(None);
    };

    let kind = match value.kind {
        winenv::ValueKind::Sz => ValueKind::Sz,
        winenv::ValueKind::ExpandSz => ValueKind::ExpandSz,
        // Spelled out rather than a wildcard, so adding a kind to `winenv` is a
        // compile error here rather than a silent reclassification.
        winenv::ValueKind::Other(name) => {
            return Err(AuditError::Registry(format!(
                "{scope}\\{VALUE_NAME} is {name}, expected REG_SZ or REG_EXPAND_SZ"
            )));
        }
    };

    Ok(Some(ScopeValue {
        text: value.text,
        kind,
    }))
}
