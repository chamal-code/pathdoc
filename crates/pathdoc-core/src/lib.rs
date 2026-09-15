//! Read-only auditing of the Windows `PATH`.
//!
//! This crate is presentation-free by design: it returns data structures and
//! never prints. All formatting belongs to the front end, so that a GUI can
//! consume the same core later without shelling out to a CLI and scraping text.
//!
//! Serialisation is a different matter to formatting, and lives here behind the
//! `serde` feature. The types below *are* the contract, whether a consumer links
//! this library and gets Rust values or reads JSON from `pathdoc --json`. Keeping
//! one definition of that shape is what stops the two from drifting apart. See
//! [`JsonReport`] for the versioned envelope, and `docs/SPEC.md` for the field
//! names it produces.

mod compose;
mod probe;
mod registry;

/// Version of the serialised report shape.
///
/// Bumped only for a change a consumer could break on: a field removed or
/// renamed, an enum representation altered, or the meaning of an existing field
/// changed. Adding a field, an enum variant, or a [`Capability`] is additive and
/// does not bump it.
pub const SCHEMA_VERSION: u32 = 1;

/// Where a `PATH` entry came from.
///
/// Windows composes the effective `PATH` as machine entries first, then user
/// entries. That ordering is load-bearing: it is why a `Program Files` install
/// outranks a copy vendored into some application's private folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ValueKind {
    /// `REG_SZ` — stored literally, no expansion.
    #[cfg_attr(feature = "serde", serde(rename = "REG_SZ"))]
    Sz,
    /// `REG_EXPAND_SZ` — environment references expanded on read.
    #[cfg_attr(feature = "serde", serde(rename = "REG_EXPAND_SZ"))]
    ExpandSz,
}

/// Something worth reporting about a single `PATH` entry.
///
/// Serialises as a discriminated union — `{"kind": "missing"}`, or
/// `{"kind": "duplicate", "firstSeenAt": 0}` — so a typed consumer can switch on
/// one field rather than probing for shapes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(
        tag = "kind",
        rename_all = "camelCase",
        rename_all_fields = "camelCase"
    )
)]
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

/// A class of analysis an audit run actually performed.
///
/// The point of this is to keep an empty result distinguishable from an absent
/// one. An empty [`AuditReport::shadows`] means "nothing is shadowed" when
/// [`Capability::ShadowDetection`] is listed, and "not computed" when it is not —
/// and a consumer that cannot tell those apart will show a clean bill of health
/// for work that never ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub enum Capability {
    /// `PATH` was read from both registry scopes and composed in the order
    /// Windows resolves.
    Composition,
    /// Per-entry findings were evaluated.
    EntryFindings,
    /// Executables were enumerated and shadowing resolved.
    ShadowDetection,
}

/// One directory on the composed `PATH`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
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
    ///
    /// Deliberately not a serialised field. It is `expanded ?? raw`, and a
    /// derived field in the wire shape is a field that can contradict the two it
    /// derives from.
    #[must_use]
    pub fn effective(&self) -> &str {
        self.expanded.as_deref().unwrap_or(&self.raw)
    }
}

/// One executable file found inside a `PATH` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
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
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Shadowed {
    /// Lower-cased file stem, since Windows resolution is case-insensitive.
    pub stem: String,
    /// Every place the stem was found, in composed `PATH` order. The first
    /// element is the one that wins.
    pub occurrences: Vec<Occurrence>,
}

/// The result of one audit run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditReport {
    /// Every entry on the composed `PATH`, in order.
    pub entries: Vec<PathEntry>,
    /// Executable names resolvable from more than one entry.
    pub shadows: Vec<Shadowed>,
    /// What this run actually computed. See [`Capability`].
    pub capabilities: Vec<Capability>,
}

impl AuditReport {
    /// Whether the audit found anything worth a non-zero exit code.
    #[must_use]
    pub fn has_findings(&self) -> bool {
        self.entries.iter().any(|e| !e.findings.is_empty()) || !self.shadows.is_empty()
    }

    /// Whether this run performed a given class of analysis.
    #[must_use]
    pub fn computed(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }
}

/// The serialised form of an [`AuditReport`], carrying the schema version.
///
/// Separate from `AuditReport` so the in-memory model stays free of wire
/// concerns, and so the version travels with the data rather than being
/// something a front end remembers to add. `entries` and `shadows` may be a
/// filtered subset of a report when a front end was asked to narrow the output;
/// `index` remains the true composed index in every case, so a filtered list
/// still says where each entry really sits.
#[cfg(feature = "serde")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonReport {
    /// Value of [`SCHEMA_VERSION`] at the time of writing.
    pub schema_version: u32,
    /// What the run computed, copied from [`AuditReport::capabilities`].
    pub capabilities: Vec<Capability>,
    /// Composed `PATH` entries, possibly filtered.
    pub entries: Vec<PathEntry>,
    /// Shadowed executable names, possibly filtered.
    pub shadows: Vec<Shadowed>,
}

#[cfg(feature = "serde")]
impl From<AuditReport> for JsonReport {
    fn from(report: AuditReport) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            capabilities: report.capabilities,
            entries: report.entries,
            shadows: report.shadows,
        }
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
/// are the next task, so [`AuditReport::shadows`] is always empty for now and
/// [`Capability::ShadowDetection`] is deliberately absent from the returned
/// capabilities.
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
        capabilities: vec![Capability::Composition, Capability::EntryFindings],
    })
}

#[cfg(test)]
mod tests {
    use super::{AuditReport, Capability, PathEntry, PathScope, audit};

    #[test]
    fn empty_report_has_no_findings() {
        assert!(!AuditReport::default().has_findings());
    }

    #[test]
    fn a_default_report_claims_to_have_computed_nothing() {
        let report = AuditReport::default();
        assert!(!report.computed(Capability::Composition));
        assert!(!report.computed(Capability::ShadowDetection));
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

    #[test]
    fn audit_reports_what_it_did_and_did_not_compute() {
        match audit() {
            Ok(report) => {
                assert!(report.computed(Capability::Composition));
                assert!(report.computed(Capability::EntryFindings));
                // Not yet built. An empty `shadows` must not read as clean.
                assert!(!report.computed(Capability::ShadowDetection));
                assert!(report.shadows.is_empty());
            }
            Err(err) => panic!("audit failed: {err}"),
        }
    }
}
