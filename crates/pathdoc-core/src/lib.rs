//! Read-only auditing of the Windows `PATH`.
//!
//! This crate is presentation-free by design: it returns data structures and
//! never prints. All formatting belongs to the front end, so that a GUI can
//! consume the same core later without shelling out to a CLI and scraping text.
//!
//! See `docs/SPEC.md` for the behaviour this models.

mod compose;
mod probe;
mod registry;

/// Where a `PATH` entry came from.
///
/// Windows composes the effective `PATH` as machine entries first, then user
/// entries. That ordering is load-bearing: it is why a `Program Files` install
/// outranks a copy vendored into some application's private folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathScope {
    /// `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
    Machine,
    /// `HKCU\Environment`
    User,
    /// Present in the live process `PATH` but in neither registry scope.
    ///
    /// Legitimate: per-shell shim directories such as `fnm`'s multishell path
    /// are injected at runtime and must not be reported as a problem.
    ProcessOnly,
}

/// The registry value type a `PATH` was stored under.
///
/// Worth distinguishing: `%USERPROFILE%\.cargo\bin` stored literally is not the
/// same fact as the same path stored already expanded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueKind {
    /// `REG_SZ` — stored literally, no expansion.
    Sz,
    /// `REG_EXPAND_SZ` — environment references expanded on read.
    ExpandSz,
}

/// Something worth reporting about a single `PATH` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// The directory does not exist.
    Missing,
    /// The path exists but is a file, not a directory.
    NotADirectory,
    /// The same canonical path appears earlier in the composed order.
    Duplicate {
        /// Index of the earlier entry this duplicates.
        first_seen_at: usize,
    },
    /// An empty segment, usually a stray separator.
    Empty,
    /// Not absolute, so resolution depends on the current directory.
    Relative,
    /// Exists, but enumeration failed — typically denied by an ACL.
    Unreadable,
}

/// One directory on the composed `PATH`.
#[derive(Debug, Clone)]
pub struct PathEntry {
    /// Zero-based position in the composed order.
    pub index: usize,
    /// Which scope contributed this entry.
    pub scope: PathScope,
    /// The value exactly as stored, before expansion.
    pub raw: String,
    /// The value after environment expansion, when it differs from `raw`.
    pub expanded: Option<String>,
    /// Registry value type, where the entry came from the registry.
    pub value_kind: Option<ValueKind>,
    /// Everything noteworthy about this entry. Empty means healthy.
    pub findings: Vec<Finding>,
}

impl PathEntry {
    /// The directory Windows actually resolves for this entry: the expansion
    /// where there was one, otherwise the raw value.
    #[must_use]
    pub fn effective(&self) -> &str {
        self.expanded.as_deref().unwrap_or(&self.raw)
    }
}

/// One executable file found inside a `PATH` entry.
#[derive(Debug, Clone)]
pub struct Occurrence {
    /// Index of the `PathEntry` that contains it.
    pub entry_index: usize,
    /// File name including extension, as it appears on disk.
    pub file_name: String,
    /// Reported rather than followed, so Store alias stubs stay distinguishable
    /// from real binaries.
    pub is_reparse_point: bool,
}

/// An executable name that exists in more than one `PATH` entry.
#[derive(Debug, Clone)]
pub struct Shadowed {
    /// Lower-cased file stem, since Windows resolution is case-insensitive.
    pub stem: String,
    /// Every place the stem was found, in composed `PATH` order. The first
    /// element is the one that wins.
    pub occurrences: Vec<Occurrence>,
}

/// The result of one audit run.
#[derive(Debug, Clone, Default)]
pub struct AuditReport {
    /// Every entry on the composed `PATH`, in order.
    pub entries: Vec<PathEntry>,
    /// Executable names resolvable from more than one entry.
    pub shadows: Vec<Shadowed>,
}

impl AuditReport {
    /// Whether the audit found anything worth a non-zero exit code.
    #[must_use]
    pub fn has_findings(&self) -> bool {
        self.entries.iter().any(|e| !e.findings.is_empty()) || !self.shadows.is_empty()
    }
}

/// Errors that make an audit impossible.
#[derive(Debug)]
pub enum AuditError {
    /// A registry key could not be opened or read.
    Registry(String),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Registry(detail) => write!(f, "cannot read PATH from the registry: {detail}"),
        }
    }
}

impl std::error::Error for AuditError {}

/// Audit the Windows `PATH`.
///
/// Reads the stored value from both registry scopes, composes them the way
/// Windows does, then adds per-entry findings. The live process `PATH` is read
/// too, but only to discover directories injected at runtime.
///
/// # Errors
///
/// Returns [`AuditError::Registry`] when the machine or user environment key
/// cannot be read. A scope that simply has no `Path` value is not an error; it
/// contributes no entries.
///
/// # Implementation status
///
/// Composition and per-entry findings are implemented. Executable enumeration,
/// `PATHEXT` handling, shadow detection and the [`Finding::Unreadable`] verdict
/// are the next task, so [`AuditReport::shadows`] is always empty for now.
pub fn audit() -> Result<AuditReport, AuditError> {
    let machine = registry::read_machine_path()?;
    let user = registry::read_user_path()?;
    let process = std::env::var("PATH").ok();

    // Environment lookups on Windows are case-insensitive, so `%SystemRoot%`
    // and `%SYSTEMROOT%` both resolve through this.
    let lookup = |name: &str| std::env::var(name).ok();

    let mut entries =
        compose::compose(machine.as_ref(), user.as_ref(), process.as_deref(), &lookup);
    probe::annotate(&mut entries);

    Ok(AuditReport {
        entries,
        shadows: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::{AuditReport, PathEntry, PathScope, audit};

    #[test]
    fn empty_report_has_no_findings() {
        assert!(!AuditReport::default().has_findings());
    }

    #[test]
    fn the_effective_value_prefers_the_expansion() {
        let mut entry = PathEntry {
            index: 0,
            scope: PathScope::Machine,
            raw: r"%SystemRoot%".to_owned(),
            expanded: None,
            value_kind: None,
            findings: Vec::new(),
        };
        assert_eq!(entry.effective(), r"%SystemRoot%");

        entry.expanded = Some(r"C:\WINDOWS".to_owned());
        assert_eq!(entry.effective(), r"C:\WINDOWS");
    }

    #[test]
    fn audit_reads_the_registry_and_composes_something() {
        // Portable: every Windows machine has a machine `PATH`, so the composed
        // list cannot be empty. What is *in* it is asserted by the machine
        // specific integration test.
        match audit() {
            Ok(report) => {
                assert!(!report.entries.is_empty());
                for (position, entry) in report.entries.iter().enumerate() {
                    assert_eq!(entry.index, position);
                }
            }
            Err(err) => panic!("audit failed: {err}"),
        }
    }
}
