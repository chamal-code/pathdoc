//! Filesystem findings for already-composed entries.
//!
//! Kept apart from `compose` so that everything order-related stays pure, and
//! only this module touches the disk.

use std::fs;
use std::io::ErrorKind;

use crate::{Finding, PathEntry};

/// Add the filesystem findings to each entry, in place.
///
/// Runs after `compose`, so an entry's findings read as the order-dependent ones
/// first and then these.
pub(crate) fn annotate(entries: &mut [PathEntry]) {
    for entry in entries {
        let target = entry.effective().to_owned();
        if target.is_empty() {
            continue;
        }

        match fs::metadata(&target) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => entry.findings.push(Finding::NotADirectory),
            Err(err) if err.kind() == ErrorKind::NotFound => {
                entry.findings.push(Finding::Missing);
            }
            // Anything else means we could not tell. Reporting `Missing` would be
            // a lie, and `Unreadable` is about failing to *enumerate* a directory
            // that does exist, which needs the enumeration slice first.
            Err(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::annotate;
    use crate::{Finding, PathEntry, PathScope};

    /// A real directory, a real file and a name that is neither, all created
    /// under the system temp directory so the test carries no assumptions about
    /// the machine it runs on.
    struct Sandbox {
        root: std::path::PathBuf,
    }

    impl Sandbox {
        fn new(label: &str) -> Self {
            let root =
                std::env::temp_dir().join(format!("pathdoc-probe-{label}-{}", std::process::id()));
            if let Err(err) = std::fs::create_dir_all(&root) {
                panic!("cannot create {}: {err}", root.display());
            }
            Self { root }
        }

        fn file(&self, name: &str) -> std::path::PathBuf {
            let path = self.root.join(name);
            if let Err(err) = std::fs::write(&path, b"not a directory") {
                panic!("cannot write {}: {err}", path.display());
            }
            path
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn entry(index: usize, raw: &str) -> PathEntry {
        PathEntry {
            index,
            scope: PathScope::Machine,
            raw: raw.to_owned(),
            expanded: None,
            value_kind: None,
            findings: Vec::new(),
        }
    }

    #[test]
    fn a_real_directory_gets_no_findings() {
        let sandbox = Sandbox::new("dir");
        let mut entries = vec![entry(0, &sandbox.root.to_string_lossy())];

        annotate(&mut entries);

        assert!(entries[0].findings.is_empty());
    }

    #[test]
    fn a_file_on_the_path_is_not_a_directory() {
        let sandbox = Sandbox::new("file");
        let file = sandbox.file("stray.txt");
        let mut entries = vec![entry(0, &file.to_string_lossy())];

        annotate(&mut entries);

        assert_eq!(entries[0].findings, vec![Finding::NotADirectory]);
    }

    #[test]
    fn an_absent_directory_is_missing() {
        let sandbox = Sandbox::new("absent");
        let absent = sandbox.root.join("no-such-directory");
        let mut entries = vec![entry(0, &absent.to_string_lossy())];

        annotate(&mut entries);

        assert_eq!(entries[0].findings, vec![Finding::Missing]);
    }

    #[test]
    fn the_expanded_form_is_what_gets_probed() {
        let sandbox = Sandbox::new("expanded");
        let mut probed = entry(0, "%SOMETHING%");
        probed.expanded = Some(sandbox.root.to_string_lossy().into_owned());
        let mut entries = vec![probed];

        annotate(&mut entries);

        assert!(entries[0].findings.is_empty());
    }

    #[test]
    fn an_empty_entry_is_not_probed() {
        let mut entries = vec![entry(0, "")];

        annotate(&mut entries);

        // `Empty` is compose's business; there is nothing on disk to check.
        assert!(entries[0].findings.is_empty());
    }
}
