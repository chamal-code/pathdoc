//! Read Windows environment variables out of the registry.
//!
//! Read-only throughout: nothing here opens a key for write.
//!
//! # Why this is its own crate
//!
//! It knows nothing about `PATH`. No splitting on `;`, no machine-before-user
//! composition, no notion of a directory. It answers one question — what is stored
//! under this name, in this scope, and what kind of value is it — and leaves every
//! interpretation to the caller.
//!
//! That boundary exists because more than one tool needs it. `pathdoc` composes and
//! audits `PATH`; a backup-and-diff tool cares about every variable and nothing
//! about `PATH` semantics. Had the second one depended on the first it would have
//! inherited `PathEntry`, `Resolved` and `AuditReport`, none of which mean anything
//! to it. Dependencies point from each tool at this crate, never from one tool at
//! another.
//!
//! # Values come back unexpanded
//!
//! This is the property everything else depends on. A `REG_EXPAND_SZ` holding
//! `%SystemRoot%\system32` is returned as exactly that text, with the kind recorded
//! alongside, so a caller can report the stored form and the resolved form as the
//! two separate facts they are.
//!
//! Reading through `[Environment]::GetEnvironmentVariable` or
//! `Get-ItemProperty` instead would expand on the way out, and writing that back is
//! how an indirection silently becomes a literal.

use std::io::ErrorKind;

use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, RegType};
use winreg::types::FromRegValue;

/// Which environment block to read.
///
/// Windows composes a process environment from the machine block first and the
/// user block second, but that is the caller's business, not this crate's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
    Machine,
    /// `HKCU\Environment`
    User,
}

impl Scope {
    /// The subkey holding this block, relative to its hive.
    #[must_use]
    pub const fn subkey(self) -> &'static str {
        match self {
            Self::Machine => r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            Self::User => "Environment",
        }
    }

    /// The hive's short name, for error messages.
    #[must_use]
    pub const fn hive(self) -> &'static str {
        match self {
            Self::Machine => "HKLM",
            Self::User => "HKCU",
        }
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}\\{}", self.hive(), self.subkey())
    }
}

/// The registry type a value was stored under.
///
/// Only the two string kinds an environment variable should ever use are named.
/// Anything else is reported rather than rejected here, because whether it is a
/// problem depends on what the caller wanted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueKind {
    /// `REG_SZ` — stored literally, no expansion.
    Sz,
    /// `REG_EXPAND_SZ` — the caller is expected to expand `%NAME%` references.
    ExpandSz,
    /// Something else, carrying the registry type name for diagnostics.
    Other(String),
}

impl std::fmt::Display for ValueKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sz => write!(f, "REG_SZ"),
            Self::ExpandSz => write!(f, "REG_EXPAND_SZ"),
            Self::Other(name) => write!(f, "{name}"),
        }
    }
}

/// One environment variable exactly as the registry stores it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Value {
    /// The stored text, **unexpanded**.
    pub text: String,
    /// The registry type it was stored under.
    pub kind: ValueKind,
}

/// A registry read that could not be completed.
#[derive(Debug)]
pub enum Error {
    /// A key or value could not be opened, read, or decoded.
    Registry {
        /// What was being read, for the message.
        location: String,
        /// The underlying reason.
        detail: String,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Registry { location, detail } => write!(f, "{location}: {detail}"),
        }
    }
}

impl std::error::Error for Error {}

/// Read one environment variable.
///
/// `Ok(None)` means the key or the value simply is not there, which is a fact
/// about the machine rather than a failure — plenty of users have no `PATH` of
/// their own. Value names are case-insensitive, so `PATH` and `Path` reach the
/// same value.
///
/// # Errors
///
/// Returns [`Error::Registry`] when the key exists but cannot be opened, or the
/// value exists but cannot be read or decoded.
pub fn read(scope: Scope, name: &str) -> Result<Option<Value>, Error> {
    let Some(key) = open(scope)? else {
        return Ok(None);
    };

    let raw = match key.get_raw_value(name) {
        Ok(raw) => raw,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(Error::Registry {
                location: format!("{scope}\\{name}"),
                detail: format!("cannot read: {err}"),
            });
        }
    };

    let kind = match raw.vtype {
        RegType::REG_SZ => ValueKind::Sz,
        RegType::REG_EXPAND_SZ => ValueKind::ExpandSz,
        ref other => ValueKind::Other(format!("{other:?}")),
    };

    // Decodes the UTF-16 bytes and trims the trailing NUL. It does **not** expand
    // environment references, which is the property this crate exists to preserve.
    let text = String::from_reg_value(&raw).map_err(|err| Error::Registry {
        location: format!("{scope}\\{name}"),
        detail: format!("cannot decode: {err}"),
    })?;

    Ok(Some(Value { text, kind }))
}

/// Every variable name defined in a scope, in the order the registry returns them.
///
/// `Ok(vec![])` when the key is absent.
///
/// # Errors
///
/// Returns [`Error::Registry`] when the key exists but cannot be opened or
/// enumerated.
pub fn names(scope: Scope) -> Result<Vec<String>, Error> {
    let Some(key) = open(scope)? else {
        return Ok(Vec::new());
    };

    let mut names = Vec::new();
    for entry in key.enum_values() {
        match entry {
            Ok((name, _)) => names.push(name),
            Err(err) => {
                return Err(Error::Registry {
                    location: scope.to_string(),
                    detail: format!("cannot enumerate: {err}"),
                });
            }
        }
    }

    Ok(names)
}

/// Open a scope's key for reading. `Ok(None)` when it does not exist.
fn open(scope: Scope) -> Result<Option<RegKey>, Error> {
    let hive = match scope {
        Scope::Machine => RegKey::predef(HKEY_LOCAL_MACHINE),
        Scope::User => RegKey::predef(HKEY_CURRENT_USER),
    };

    match hive.open_subkey_with_flags(scope.subkey(), KEY_READ) {
        Ok(key) => Ok(Some(key)),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(Error::Registry {
            location: scope.to_string(),
            detail: format!("cannot open: {err}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{Scope, ValueKind, names, read};

    #[test]
    fn scopes_name_the_keys_windows_uses() {
        assert_eq!(
            Scope::Machine.subkey(),
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
        );
        assert_eq!(Scope::User.subkey(), "Environment");
        assert_eq!(Scope::Machine.hive(), "HKLM");
        assert_eq!(Scope::User.hive(), "HKCU");
    }

    #[test]
    fn a_scope_displays_as_its_full_key_path() {
        assert_eq!(Scope::User.to_string(), r"HKCU\Environment");
    }

    #[test]
    fn value_kinds_display_as_their_registry_names() {
        // Somebody reading a message from this crate probably has regedit open.
        assert_eq!(ValueKind::Sz.to_string(), "REG_SZ");
        assert_eq!(ValueKind::ExpandSz.to_string(), "REG_EXPAND_SZ");
        assert_eq!(
            ValueKind::Other("REG_DWORD".to_owned()).to_string(),
            "REG_DWORD"
        );
    }

    #[test]
    fn a_name_that_is_not_there_is_absent_rather_than_an_error() {
        match read(Scope::User, "pathdoc-no-such-variable") {
            Ok(value) => assert_eq!(value, None),
            Err(err) => panic!("expected absence, got an error: {err}"),
        }
    }

    #[test]
    fn the_machine_path_is_readable_as_a_string_value() {
        // HKLM always defines Path on Windows. The kind is asserted only to be one of
        // the two string kinds: whether it is specifically REG_EXPAND_SZ is a fact
        // about how a given machine was configured, and something that appends via
        // `[Environment]::SetEnvironmentVariable` will have flattened it to REG_SZ.
        // The strict version belongs in `this_machine.rs`, where it is checked against
        // a machine somebody has actually looked at.
        let value = match read(Scope::Machine, "Path") {
            Ok(Some(value)) => value,
            Ok(None) => panic!("the machine scope has no Path"),
            Err(err) => panic!("cannot read the machine Path: {err}"),
        };

        assert!(!value.text.is_empty());
        assert!(
            matches!(value.kind, ValueKind::Sz | ValueKind::ExpandSz),
            "expected a string kind, got {}",
            value.kind
        );
    }

    #[test]
    fn values_come_back_unexpanded() {
        // The property everything else depends on. Windows ships the machine Path
        // holding `%SystemRoot%` references, so on an untouched machine there is
        // something to check.
        let value = match read(Scope::Machine, "Path") {
            Ok(Some(value)) => value,
            other => panic!("cannot read the machine Path: {other:?}"),
        };

        if value.kind != ValueKind::ExpandSz || !value.text.contains('%') {
            // Nothing to prove: this machine's Path holds no references, so an
            // expanding read and a non-expanding one would return the same bytes.
            // Said out loud rather than passing quietly, so a vacuous pass is not
            // mistaken for a verified one. `this_machine.rs` asserts the strict
            // version against real `%SystemRoot%` entries.
            eprintln!(
                "skipped: the machine Path holds no environment references here, \
                 so unexpanded reading cannot be distinguished"
            );
            return;
        }

        assert!(
            value.text.contains('%'),
            "expected an unexpanded reference, got {:?}",
            value.text
        );
    }

    #[test]
    fn a_value_name_is_matched_case_insensitively() {
        let lower = read(Scope::Machine, "path");
        let mixed = read(Scope::Machine, "Path");

        match (lower, mixed) {
            (Ok(lower), Ok(mixed)) => assert_eq!(lower, mixed),
            other => panic!("reads disagreed: {other:?}"),
        }
    }

    #[test]
    fn names_can_be_enumerated() {
        // The half a backup-and-diff tool needs.
        //
        // Only the machine scope is asserted to define `Path`. Windows always does,
        // whereas a user profile with no variables of its own is perfectly legal —
        // a fresh CI runner is the obvious case — so requiring one there would be
        // asserting a fact about this machine in a portable test.
        let machine = match names(Scope::Machine) {
            Ok(names) => names,
            Err(err) => panic!("cannot enumerate {}: {err}", Scope::Machine),
        };
        assert!(
            machine.iter().any(|name| name.eq_ignore_ascii_case("path")),
            "the machine scope defines no Path; got {machine:?}"
        );

        // For the user scope the portable claim is only that enumeration works.
        if let Err(err) = names(Scope::User) {
            panic!("cannot enumerate {}: {err}", Scope::User);
        }
    }
}
