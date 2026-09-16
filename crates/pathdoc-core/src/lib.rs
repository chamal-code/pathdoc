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
mod executables;
mod probe;
mod registry;

/// Version of the serialised report shape.
///
/// Bumped only for a change a consumer could break on: a field removed or
/// renamed, an enum representation altered, or the meaning of an existing field
/// changed. Adding a field, an enum variant, or a [`Capability`] is additive and
/// does not bump it.
///
/// `2` replaced a `shadows` array holding only contested names with an
/// [`AuditReport::executables`] array holding every name found. Reason: on the
/// machine this was built for, three of the four executables worth reporting —
/// `gzip`, `unzip`, `sdiff` — appear exactly once, so a conflicts-only list could
/// never have named them. "Where does this come from" turned out to be as much of
/// a question as "which one wins".
pub const SCHEMA_VERSION: u32 = 2;

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
    /// Index of the [`PathEntry`] that contains it, in the full composed order.
    pub entry_index: usize,
    /// The directory it was found in — the containing entry's effective value.
    ///
    /// Denormalised on purpose. A front end may report a filtered subset of
    /// entries, and an occurrence that can only be understood by joining against
    /// an array that might not be there is not much of a fact.
    pub directory: String,
    /// File name including extension, as it appears on disk.
    pub file_name: String,
    /// Reported rather than followed, so Store alias stubs stay distinguishable
    /// from real binaries.
    pub is_reparse_point: bool,
}

/// Every place one executable name resolves from.
///
/// Recorded for every name found, not only the contested ones. That is a
/// correction to an earlier design: of the four executables this tool was written
/// to expose on its home machine, three (`gzip`, `unzip`, `sdiff`) appear exactly
/// once, and a conflicts-only list could never have reported them. Where a name
/// comes from is a fact worth having even when nothing competes for it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Resolved {
    /// Lower-cased file stem, since Windows resolution is case-insensitive.
    pub stem: String,
    /// Every place the stem was found, in the order Windows tries them: composed
    /// `PATH` order first, then `PATHEXT` order within a single directory. The
    /// first element is the one that wins.
    pub occurrences: Vec<Occurrence>,
}

impl Resolved {
    /// The occurrence Windows would actually run.
    #[must_use]
    pub fn winner(&self) -> Option<&Occurrence> {
        self.occurrences.first()
    }

    /// Whether more than one file answers to this name.
    #[must_use]
    pub fn is_shadowed(&self) -> bool {
        self.occurrences.len() > 1
    }

    /// Whether every occurrence sits in the same directory, making this a contest
    /// decided by `PATHEXT` order rather than by `PATH` order.
    ///
    /// Worth separating because it surprises people: `foo.com` beats `foo.exe`,
    /// and no amount of reordering `PATH` will change that.
    #[must_use]
    pub fn is_pathext_only(&self) -> bool {
        match self.occurrences.split_first() {
            Some((first, rest)) => {
                !rest.is_empty()
                    && rest
                        .iter()
                        .all(|other| other.entry_index == first.entry_index)
            }
            None => false,
        }
    }
}

/// The result of one audit run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditReport {
    /// Every entry on the composed `PATH`, in order.
    pub entries: Vec<PathEntry>,
    /// Every executable name found, sorted by stem. See [`Resolved`].
    pub executables: Vec<Resolved>,
    /// What this run actually computed. See [`Capability`].
    pub capabilities: Vec<Capability>,
}

impl AuditReport {
    /// Whether the audit found anything worth a non-zero exit code.
    #[must_use]
    pub fn has_findings(&self) -> bool {
        self.entries.iter().any(|e| !e.findings.is_empty()) || self.shadowed().next().is_some()
    }

    /// Only the names more than one file answers to.
    pub fn shadowed(&self) -> impl Iterator<Item = &Resolved> {
        self.executables
            .iter()
            .filter(|resolved| resolved.is_shadowed())
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
    /// Every executable name found. Never filtered by scope: which copy of a name
    /// wins is decided across the whole `PATH`, so a scoped answer would be wrong
    /// rather than merely narrower.
    pub executables: Vec<Resolved>,
}

#[cfg(feature = "serde")]
impl From<AuditReport> for JsonReport {
    fn from(report: AuditReport) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            capabilities: report.capabilities,
            entries: report.entries,
            executables: report.executables,
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
/// Then enumerates the executables in each surviving directory and works out
/// which copy of each name Windows would actually run.
pub fn audit() -> Result<AuditReport, AuditError> {
    let machine = registry::read_machine_path()?;
    let user = registry::read_user_path()?;
    let process = std::env::var("PATH").ok();

    // Environment lookups on Windows are case-insensitive, so `%SystemRoot%`
    // and `%SYSTEMROOT%` both resolve through this.
    let lookup = |name: &str| std::env::var(name).ok();

    let mut entries =
        compose::compose(machine.as_ref(), user.as_ref(), process.as_deref(), &lookup);

    // Order matters: the filesystem probe decides which entries are worth
    // enumerating, and enumeration is what can add `Unreadable`.
    probe::annotate(&mut entries);
    let extensions = executables::extensions(&lookup);
    let executables = executables::enumerate(&mut entries, &extensions);

    Ok(AuditReport {
        entries,
        executables,
        capabilities: vec![
            Capability::Composition,
            Capability::EntryFindings,
            Capability::ShadowDetection,
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::{AuditReport, Capability, Occurrence, PathEntry, PathScope, Resolved, audit};

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
    fn audit_reports_what_it_computed() {
        match audit() {
            Ok(report) => {
                assert!(report.computed(Capability::Composition));
                assert!(report.computed(Capability::EntryFindings));
                assert!(report.computed(Capability::ShadowDetection));
            }
            Err(err) => panic!("audit failed: {err}"),
        }
    }

    #[test]
    fn audit_finds_executables_and_shadowing_is_a_subset_of_them() {
        // Portable: `system32` alone guarantees both, since it ships several names
        // under two extensions apiece.
        match audit() {
            Ok(report) => {
                assert!(!report.executables.is_empty());
                let shadowed = report.shadowed().count();
                assert!(shadowed <= report.executables.len());
                for resolved in report.shadowed() {
                    assert!(resolved.occurrences.len() > 1);
                }
            }
            Err(err) => panic!("audit failed: {err}"),
        }
    }

    #[test]
    fn a_single_occurrence_is_not_shadowed() {
        let resolved = Resolved {
            stem: "gzip".to_owned(),
            occurrences: vec![Occurrence {
                entry_index: 17,
                directory: r"C:\vendored\usr\bin".to_owned(),
                file_name: "gzip.exe".to_owned(),
                is_reparse_point: false,
            }],
        };

        assert!(!resolved.is_shadowed());
        assert!(!resolved.is_pathext_only());
        assert_eq!(
            resolved.winner().map(|occurrence| occurrence.entry_index),
            Some(17)
        );
    }

    #[test]
    fn a_contest_inside_one_directory_is_decided_by_pathext() {
        let occurrence = |file_name: &str| Occurrence {
            entry_index: 0,
            directory: r"C:\WINDOWS\system32".to_owned(),
            file_name: file_name.to_owned(),
            is_reparse_point: false,
        };
        let resolved = Resolved {
            stem: "powercfg".to_owned(),
            occurrences: vec![occurrence("powercfg.exe"), occurrence("powercfg.cpl")],
        };

        assert!(resolved.is_shadowed());
        assert!(resolved.is_pathext_only());
    }
}
