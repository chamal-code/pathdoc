//! Command-line front end for `pathdoc-core`.
//!
//! All formatting lives here. The core crate returns data and never prints.
//!
//! Exit codes, matching the convention used across this machine's tooling:
//! `0` nothing to report, `1` findings present, `2` fatal error. The code
//! describes what was *reported*, so narrowing the output with `--scope` narrows
//! what can make it non-zero.

mod json;
mod options;
mod table;

use std::io::{self, Write};
use std::process::ExitCode;

use clap::Parser;
use pathdoc_core::{AuditReport, PathEntry};

use crate::options::Options;

/// Exit code for a clean audit.
const EXIT_CLEAN: u8 = 0;
/// Exit code when the audit found something worth reporting.
const EXIT_FINDINGS: u8 = 1;
/// Exit code for a fatal error.
const EXIT_FATAL: u8 = 2;

fn main() -> ExitCode {
    // clap exits with 2 on a usage error, which is already the convention here.
    let options = Options::parse();

    if options.no_color {
        // Otherwise anstream decides for itself, honouring NO_COLOR, CLICOLOR and
        // whether the destination is a terminal.
        anstream::ColorChoice::Never.write_global();
    }

    match run(&options) {
        Ok(true) => ExitCode::from(EXIT_FINDINGS),
        Ok(false) => ExitCode::from(EXIT_CLEAN),
        Err(err) => {
            eprintln!("pathdoc: {err}");
            ExitCode::from(EXIT_FATAL)
        }
    }
}

/// Run the audit and write it out. `Ok(true)` means findings were reported.
fn run(options: &Options) -> Result<bool, Box<dyn std::error::Error>> {
    let report = pathdoc_core::audit()?;

    let entries: Vec<&PathEntry> = report
        .entries
        .iter()
        .filter(|entry| options.includes(entry))
        .collect();

    let mut out = anstream::stdout().lock();
    let written = if options.json {
        json::write_json(&mut out, &report, &entries, options.shadows_only)
    } else {
        table::write_report(&mut out, &report, &entries, options.shadows_only)
    }
    .and_then(|()| out.flush());

    match written {
        Ok(()) => {}
        // `pathdoc | head` closes the pipe early. Nothing went wrong.
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => return Ok(false),
        Err(err) => return Err(err.into()),
    }

    Ok(reported_findings(&report, &entries, options.shadows_only))
}

/// Whether the output actually contained a finding.
///
/// Deliberately about the reported view rather than the whole audit, so
/// `pathdoc --scope machine` succeeds when the only problem is in the user scope.
/// That makes the flag composable in a script instead of a lie waiting to happen.
fn reported_findings(report: &AuditReport, entries: &[&PathEntry], shadows_only: bool) -> bool {
    let entry_findings = !shadows_only && entries.iter().any(|entry| !entry.findings.is_empty());

    // `executables` holds every name found, around a thousand of them, so the
    // question is whether any of them is contested — not whether the list is empty.
    entry_findings || report.shadowed().next().is_some()
}

#[cfg(test)]
mod tests {
    use super::reported_findings;
    use pathdoc_core::{
        AuditReport, Capability, Finding, Occurrence, PathEntry, PathScope, Resolved, ValueKind,
    };

    fn entry(index: usize, scope: PathScope, findings: Vec<Finding>) -> PathEntry {
        PathEntry {
            index,
            scope,
            raw: r"C:\somewhere".to_owned(),
            expanded: None,
            value_kind: Some(ValueKind::Sz),
            findings,
        }
    }

    fn report(entries: Vec<PathEntry>) -> AuditReport {
        AuditReport {
            entries,
            executables: Vec::new(),
            capabilities: vec![Capability::Composition, Capability::EntryFindings],
        }
    }

    fn occurrence(entry_index: usize, file_name: &str) -> Occurrence {
        Occurrence {
            entry_index,
            directory: format!(r"C:\place{entry_index}"),
            file_name: file_name.to_owned(),
            is_reparse_point: false,
        }
    }

    #[test]
    fn a_clean_report_exits_clean() {
        let report = report(vec![entry(0, PathScope::Machine, Vec::new())]);
        let entries: Vec<&PathEntry> = report.entries.iter().collect();

        assert!(!reported_findings(&report, &entries, false));
    }

    #[test]
    fn a_finding_in_the_reported_scope_counts() {
        let report = report(vec![entry(0, PathScope::User, vec![Finding::Missing])]);
        let entries: Vec<&PathEntry> = report.entries.iter().collect();

        assert!(reported_findings(&report, &entries, false));
    }

    #[test]
    fn a_finding_outside_the_reported_scope_does_not() {
        let report = report(vec![
            entry(0, PathScope::Machine, Vec::new()),
            entry(1, PathScope::User, vec![Finding::Missing]),
        ]);
        // As `--scope machine` would filter it.
        let entries: Vec<&PathEntry> = report
            .entries
            .iter()
            .filter(|entry| entry.scope == PathScope::Machine)
            .collect();

        assert!(!reported_findings(&report, &entries, false));
    }

    #[test]
    fn a_name_that_resolves_uniquely_is_not_a_finding() {
        // The trap this guards: `executables` is never empty on a real machine, so
        // testing it for emptiness would make every run exit non-zero.
        let mut clean = report(vec![entry(0, PathScope::Machine, Vec::new())]);
        clean.capabilities.push(Capability::ShadowDetection);
        clean.executables = vec![Resolved {
            stem: "gzip".to_owned(),
            occurrences: vec![occurrence(0, "gzip.exe")],
        }];
        let entries: Vec<&PathEntry> = clean.entries.iter().collect();

        assert!(!reported_findings(&clean, &entries, false));
    }

    #[test]
    fn shadows_only_ignores_entry_findings_but_not_shadowing() {
        let mut with_shadow = report(vec![entry(0, PathScope::User, vec![Finding::Missing])]);
        let entries: Vec<&PathEntry> = with_shadow.entries.iter().collect();

        // Entry findings are not on screen, so they cannot be what failed.
        assert!(!reported_findings(&with_shadow, &entries, true));

        with_shadow.capabilities.push(Capability::ShadowDetection);
        with_shadow.executables = vec![Resolved {
            stem: "git".to_owned(),
            occurrences: vec![occurrence(0, "git.exe"), occurrence(1, "git.exe")],
        }];
        let entries: Vec<&PathEntry> = with_shadow.entries.iter().collect();

        assert!(reported_findings(&with_shadow, &entries, true));
    }
}
