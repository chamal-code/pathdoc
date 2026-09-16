//! Executable enumeration, and working out which copy of a name wins.
//!
//! Windows resolves a bare command name by walking `PATH` in order and, in each
//! directory, trying each extension in `PATHEXT` in order. Both loops matter, and
//! the inner one is the part people forget: `foo.com` beats `foo.exe` in the same
//! directory, and no amount of reordering `PATH` changes that.
//!
//! `PATHEXT` is read from the environment rather than hard-coded, which is not
//! pedantry. On the machine this was written for it is
//! `.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL` — one entry longer
//! than the documented default, and `powercfg.cpl` sits next to `powercfg.exe` in
//! `system32`, so the difference is load-bearing.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::os::windows::fs::MetadataExt;

use crate::{Finding, Occurrence, PathEntry, Resolved};

/// `PATHEXT` as Windows documents it, used only when the environment is silent.
const DEFAULT_PATHEXT: &str = ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC";

/// `FILE_ATTRIBUTE_REPARSE_POINT`. Named so the magic number is explained once.
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

/// One executable file as found on disk, before grouping by name.
struct Found {
    /// Index of the entry whose directory it was found in.
    entry_index: usize,
    /// The directory itself.
    directory: String,
    /// File name as it appears on disk, original casing.
    file_name: String,
    /// Lower-cased name with the matched extension removed.
    stem: String,
    /// Position of the matched extension within `PATHEXT`, which is the order
    /// Windows tries them in.
    extension_rank: usize,
    /// Whether the file is a reparse point, reported rather than followed.
    is_reparse_point: bool,
}

/// The executable extensions to look for, in `PATHEXT` order.
pub(crate) fn extensions<F>(lookup: &F) -> Vec<String>
where
    F: Fn(&str) -> Option<String>,
{
    let configured = lookup("PATHEXT").unwrap_or_default();
    let parsed = parse_extensions(&configured);

    if parsed.is_empty() {
        parse_extensions(DEFAULT_PATHEXT)
    } else {
        parsed
    }
}

/// Enumerate every eligible entry and group what turns up by name.
///
/// Takes the entries mutably because enumeration is the only thing that can
/// discover [`Finding::Unreadable`]: a directory that exists, and that the
/// filesystem probe was therefore happy with, but that will not open.
pub(crate) fn enumerate(entries: &mut [PathEntry], extensions: &[String]) -> Vec<Resolved> {
    let mut found: Vec<Found> = Vec::new();

    for entry in entries {
        if !is_enumerable(entry) {
            continue;
        }

        let directory = entry.effective().to_owned();
        match fs::read_dir(&directory) {
            Ok(reader) => collect(reader, entry.index, &directory, extensions, &mut found),
            Err(err) => entry.findings.push(finding_for_read_error(err.kind())),
        }
    }

    group(found)
}

/// Whether it is worth reading this entry's directory.
///
/// A duplicate is skipped because an earlier entry already names the same
/// directory: enumerating it twice would report every program in it as shadowing
/// itself, which is a whole category of false positive for nothing.
fn is_enumerable(entry: &PathEntry) -> bool {
    !entry.findings.iter().any(|finding| {
        matches!(
            finding,
            Finding::Missing | Finding::NotADirectory | Finding::Empty | Finding::Duplicate { .. }
        )
    })
}

/// What a failure to open an existing directory means.
fn finding_for_read_error(kind: io::ErrorKind) -> Finding {
    if kind == io::ErrorKind::NotFound {
        // Probed as a directory moments ago and gone now. Rare, but the honest
        // answer is the one the probe would have given.
        Finding::Missing
    } else {
        Finding::Unreadable
    }
}

/// Pull the executables out of one already-opened directory.
fn collect(
    reader: fs::ReadDir,
    entry_index: usize,
    directory: &str,
    extensions: &[String],
    found: &mut Vec<Found>,
) {
    // A single unreadable item does not make the directory unreadable, and there
    // is nothing useful to say about it, so it is skipped.
    for item in reader.flatten() {
        let file_name = item.file_name().to_string_lossy().into_owned();
        let Some((stem, extension_rank)) = classify(&file_name, extensions) else {
            continue;
        };

        // `DirEntry::metadata` does not traverse a link on Windows, which is what
        // keeps a Store alias stub identifiable instead of resolving to whatever
        // it points at.
        let Ok(metadata) = item.metadata() else {
            continue;
        };
        if metadata.is_dir() {
            // A directory called `foo.exe` is not a program.
            continue;
        }

        found.push(Found {
            entry_index,
            directory: directory.to_owned(),
            file_name,
            stem,
            extension_rank,
            is_reparse_point: metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0,
        });
    }
}

/// Sort into resolution order, then group by name.
fn group(mut found: Vec<Found>) -> Vec<Resolved> {
    // Resolution order exactly: `PATH` order, then `PATHEXT` order within a
    // directory. File name last only to keep the result stable, since `read_dir`
    // makes no promises about the order it hands things back.
    found.sort_by(|left, right| {
        left.entry_index
            .cmp(&right.entry_index)
            .then(left.extension_rank.cmp(&right.extension_rank))
            .then_with(|| left.file_name.cmp(&right.file_name))
    });

    let mut groups: HashMap<String, Vec<Occurrence>> = HashMap::new();
    for item in found {
        groups.entry(item.stem).or_default().push(Occurrence {
            entry_index: item.entry_index,
            directory: item.directory,
            file_name: item.file_name,
            is_reparse_point: item.is_reparse_point,
        });
    }

    let mut resolved: Vec<Resolved> = groups
        .into_iter()
        .map(|(stem, occurrences)| Resolved { stem, occurrences })
        .collect();
    // `HashMap` order is arbitrary; sort so the report is reproducible.
    resolved.sort_by(|left, right| left.stem.cmp(&right.stem));

    resolved
}

/// Split a `PATHEXT` value into lower-cased extensions, order preserved.
fn parse_extensions(raw: &str) -> Vec<String> {
    let mut extensions: Vec<String> = Vec::new();

    for piece in raw.split(';') {
        let trimmed = piece.trim();
        if trimmed.is_empty() {
            continue;
        }

        let lowered = trimmed.to_lowercase();
        let normalised = if lowered.starts_with('.') {
            lowered
        } else {
            format!(".{lowered}")
        };

        // A repeat would only ever match at its first rank.
        if !extensions.contains(&normalised) {
            extensions.push(normalised);
        }
    }

    extensions
}

/// The stem and `PATHEXT` rank of a file name, if it is executable at all.
///
/// Only the matched extension is removed, so `python3.11.exe` is the program
/// `python3.11` and not the program `python3`.
fn classify(file_name: &str, extensions: &[String]) -> Option<(String, usize)> {
    let lowered = file_name.to_lowercase();

    for (rank, extension) in extensions.iter().enumerate() {
        if let Some(stem) = lowered.strip_suffix(extension.as_str()) {
            // A file called exactly `.exe` names no program.
            if stem.is_empty() {
                continue;
            }
            return Some((stem.to_owned(), rank));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_PATHEXT, classify, enumerate, extensions, finding_for_read_error, is_enumerable,
        parse_extensions,
    };
    use crate::{Finding, PathEntry, PathScope};

    fn windows_pathext() -> Vec<String> {
        parse_extensions(DEFAULT_PATHEXT)
    }

    fn entry(index: usize, directory: &str, findings: Vec<Finding>) -> PathEntry {
        PathEntry {
            index,
            scope: PathScope::Machine,
            raw: directory.to_owned(),
            expanded: None,
            value_kind: None,
            findings,
        }
    }

    // ---- PATHEXT parsing, entirely portable ----

    #[test]
    fn pathext_is_read_from_the_environment() {
        let configured = |name: &str| {
            if name == "PATHEXT" {
                Some(".EXE;.CPL".to_owned())
            } else {
                None
            }
        };

        // Not the documented default, which is the point of reading it.
        assert_eq!(extensions(&configured), vec![".exe", ".cpl"]);
    }

    #[test]
    fn an_absent_or_empty_pathext_falls_back_to_the_documented_default() {
        let silent = |_: &str| None;
        let blank = |_: &str| Some(String::new());

        assert_eq!(extensions(&silent), windows_pathext());
        assert_eq!(extensions(&blank), windows_pathext());
        assert_eq!(
            extensions(&silent).first().map(String::as_str),
            Some(".com")
        );
    }

    #[test]
    fn pathext_order_is_preserved_because_it_is_precedence() {
        let parsed = windows_pathext();

        let com = parsed.iter().position(|ext| ext == ".com");
        let exe = parsed.iter().position(|ext| ext == ".exe");
        assert!(com < exe, "`.com` must outrank `.exe`");
    }

    #[test]
    fn pathext_parsing_tolerates_untidy_values() {
        // Padding, a missing dot, mixed case, a stray separator and a repeat.
        let parsed = parse_extensions(" .EXE ; bat;;.Cmd;.exe;");

        assert_eq!(parsed, vec![".exe", ".bat", ".cmd"]);
    }

    // ---- classifying file names, entirely portable ----

    #[test]
    fn only_files_with_an_executable_extension_count() {
        let pathext = windows_pathext();

        assert_eq!(classify("git.exe", &pathext), Some(("git".to_owned(), 1)));
        assert_eq!(classify("readme.md", &pathext), None);
        assert_eq!(classify("git", &pathext), None);
    }

    #[test]
    fn extension_matching_ignores_case() {
        let pathext = windows_pathext();

        // `system32` really does ship `HOSTNAME.EXE` in capitals.
        assert_eq!(
            classify("HOSTNAME.EXE", &pathext),
            classify("hostname.exe", &pathext)
        );
    }

    #[test]
    fn only_the_matched_extension_is_stripped() {
        let pathext = windows_pathext();

        // Otherwise `python3.11` and `python3` would be confused for each other,
        // and they are different programs sitting in the same directory.
        assert_eq!(
            classify("python3.11.exe", &pathext).map(|(stem, _)| stem),
            Some("python3.11".to_owned())
        );
        assert_eq!(
            classify("python3.exe", &pathext).map(|(stem, _)| stem),
            Some("python3".to_owned())
        );
    }

    #[test]
    fn a_longer_extension_is_not_confused_with_a_shorter_one() {
        let pathext = windows_pathext();

        assert_eq!(
            classify("script.jse", &pathext).map(|(stem, _)| stem),
            Some("script".to_owned())
        );
        assert_eq!(
            classify("script.js", &pathext).map(|(stem, _)| stem),
            Some("script".to_owned())
        );
        // Different extensions, so different ranks.
        assert_ne!(
            classify("script.jse", &pathext).map(|(_, rank)| rank),
            classify("script.js", &pathext).map(|(_, rank)| rank)
        );
    }

    #[test]
    fn a_bare_extension_names_no_program() {
        assert_eq!(classify(".exe", &windows_pathext()), None);
    }

    // ---- which entries get enumerated, entirely portable ----

    #[test]
    fn a_healthy_entry_is_enumerated() {
        assert!(is_enumerable(&entry(0, r"C:\one", Vec::new())));
    }

    #[test]
    fn a_duplicate_is_not_enumerated_twice() {
        // The earlier entry names the same directory. Reading it again would make
        // every program in it shadow itself.
        assert!(!is_enumerable(&entry(
            1,
            r"C:\one",
            vec![Finding::Duplicate { first_seen_at: 0 }]
        )));
    }

    #[test]
    fn there_is_nothing_to_read_in_a_broken_entry() {
        for finding in [Finding::Missing, Finding::NotADirectory, Finding::Empty] {
            assert!(!is_enumerable(&entry(0, r"C:\one", vec![finding])));
        }
    }

    #[test]
    fn a_relative_entry_is_still_enumerated() {
        // Windows would search it, so reporting what is in it is the honest answer.
        assert!(is_enumerable(&entry(0, "bin", vec![Finding::Relative])));
    }

    #[test]
    fn a_directory_that_will_not_open_is_unreadable_not_missing() {
        use std::io::ErrorKind;

        assert_eq!(
            finding_for_read_error(ErrorKind::PermissionDenied),
            Finding::Unreadable
        );
        // Vanished between the probe and the read.
        assert_eq!(
            finding_for_read_error(ErrorKind::NotFound),
            Finding::Missing
        );
    }

    // ---- enumeration against a real directory ----

    /// A temp directory holding real files, removed on drop.
    struct Sandbox {
        root: std::path::PathBuf,
    }

    impl Sandbox {
        fn new(label: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("pathdoc-exe-{label}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            if let Err(err) = std::fs::create_dir_all(&root) {
                panic!("cannot create {}: {err}", root.display());
            }
            Self { root }
        }

        fn with(self, names: &[&str]) -> Self {
            for name in names {
                let path = self.root.join(name);
                if let Err(err) = std::fs::write(&path, b"stub") {
                    panic!("cannot write {}: {err}", path.display());
                }
            }
            self
        }

        fn path(&self) -> String {
            self.root.to_string_lossy().into_owned()
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn enumeration_finds_executables_and_ignores_everything_else() {
        let sandbox = Sandbox::new("basic").with(&["tool.exe", "notes.txt", "script.cmd"]);
        let mut entries = vec![entry(0, &sandbox.path(), Vec::new())];

        let resolved = enumerate(&mut entries, &windows_pathext());

        let stems: Vec<&str> = resolved.iter().map(|item| item.stem.as_str()).collect();
        assert_eq!(
            stems,
            vec!["script", "tool"],
            "sorted by stem, no notes.txt"
        );
        assert!(entries[0].findings.is_empty());
    }

    #[test]
    fn an_occurrence_knows_its_directory_without_a_join() {
        let sandbox = Sandbox::new("directory").with(&["tool.exe"]);
        let mut entries = vec![entry(7, &sandbox.path(), Vec::new())];

        let resolved = enumerate(&mut entries, &windows_pathext());

        let Some(occurrence) = resolved.first().and_then(|item| item.winner()) else {
            panic!("tool.exe was not found")
        };
        assert_eq!(occurrence.entry_index, 7);
        assert_eq!(occurrence.directory, sandbox.path());
        assert_eq!(occurrence.file_name, "tool.exe");
        assert!(!occurrence.is_reparse_point);
    }

    #[test]
    fn path_order_decides_between_directories() {
        let first = Sandbox::new("wins").with(&["tool.exe"]);
        let second = Sandbox::new("loses").with(&["tool.exe"]);
        let mut entries = vec![
            entry(0, &first.path(), Vec::new()),
            entry(1, &second.path(), Vec::new()),
        ];

        let resolved = enumerate(&mut entries, &windows_pathext());

        assert_eq!(resolved.len(), 1);
        let tool = &resolved[0];
        assert!(tool.is_shadowed());
        assert!(!tool.is_pathext_only());
        assert_eq!(tool.occurrences.len(), 2);
        assert_eq!(tool.occurrences[0].directory, first.path());
        assert_eq!(tool.occurrences[1].directory, second.path());
    }

    #[test]
    fn pathext_order_decides_within_one_directory() {
        // `.com` outranks `.exe`, which is the surprise this exists to surface.
        let sandbox = Sandbox::new("pathext").with(&["tool.exe", "tool.com"]);
        let mut entries = vec![entry(0, &sandbox.path(), Vec::new())];

        let resolved = enumerate(&mut entries, &windows_pathext());

        assert_eq!(resolved.len(), 1);
        let tool = &resolved[0];
        assert!(tool.is_shadowed());
        assert!(
            tool.is_pathext_only(),
            "one directory, so PATH order cannot be the tie-breaker"
        );
        assert_eq!(
            tool.winner()
                .map(|occurrence| occurrence.file_name.as_str()),
            Some("tool.com")
        );
    }

    #[test]
    fn a_name_found_once_is_still_recorded() {
        // The correction that produced schema 2: `gzip` appears exactly once on
        // the home machine and is still one of the facts worth reporting.
        let sandbox = Sandbox::new("single").with(&["gzip.exe"]);
        let mut entries = vec![entry(0, &sandbox.path(), Vec::new())];

        let resolved = enumerate(&mut entries, &windows_pathext());

        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].stem, "gzip");
        assert!(!resolved[0].is_shadowed());
    }

    #[test]
    fn a_missing_directory_is_not_read_and_gains_no_new_finding() {
        let mut entries = vec![entry(
            0,
            r"C:\pathdoc-does-not-exist",
            vec![Finding::Missing],
        )];

        let resolved = enumerate(&mut entries, &windows_pathext());

        assert!(resolved.is_empty());
        assert_eq!(entries[0].findings, vec![Finding::Missing]);
    }

    /// Denies the current user read on a directory via `icacls`, and puts it back
    /// on drop. The only way to produce a genuine `Unreadable` without an ACL
    /// already lying around.
    struct Denied {
        root: std::path::PathBuf,
        account: String,
    }

    impl Denied {
        /// `None` when the deny could not be applied, so the test can skip rather
        /// than fail on a machine that does not allow this.
        fn new(root: std::path::PathBuf) -> Option<Self> {
            let account = std::env::var("USERNAME").ok()?;
            let rule = format!("{account}:(RX)");
            let applied = std::process::Command::new("icacls")
                .arg(&root)
                .arg("/deny")
                .arg(&rule)
                .output()
                .ok()?;
            if !applied.status.success() {
                return None;
            }

            let denied = Self { root, account };
            // Confirm the deny actually bites before relying on it.
            if std::fs::read_dir(&denied.root).is_ok() {
                return None;
            }
            Some(denied)
        }
    }

    impl Drop for Denied {
        fn drop(&mut self) {
            let _ = std::process::Command::new("icacls")
                .arg(&self.root)
                .arg("/remove:d")
                .arg(&self.account)
                .output();
        }
    }

    #[test]
    fn a_directory_that_denies_enumeration_is_reported_unreadable() {
        let sandbox = Sandbox::new("denied").with(&["hidden.exe"]);
        let Some(_guard) = Denied::new(sandbox.root.clone()) else {
            // Say so rather than passing quietly, otherwise a machine where the
            // deny does not apply looks like a machine where this was verified.
            eprintln!(
                "skipped: could not deny read on a temp directory, so Unreadable \
                 was not exercised end to end"
            );
            return;
        };

        let mut entries = vec![entry(0, &sandbox.path(), Vec::new())];
        let resolved = enumerate(&mut entries, &windows_pathext());

        assert_eq!(entries[0].findings, vec![Finding::Unreadable]);
        assert!(
            resolved.is_empty(),
            "nothing can be claimed about a directory that would not open"
        );
    }
}
