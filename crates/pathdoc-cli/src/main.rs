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
    let report = pathdoc_core::audit_with(
        &pathdoc_core::AuditOptions::default()
            .with_shell_scan(options.shell_scan())
            .with_shell_interpreters(options.shells.clone()),
    )?;

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

    Ok(reported_findings(&report, &entries, options))
}

/// Whether the output contained anything that should fail the run.
///
/// Two deliberate restrictions.
///
/// It is about the reported view rather than the whole audit, so
/// `pathdoc --scope machine` succeeds when the only problem is in the user scope.
/// That makes the flag composable in a script instead of a lie waiting to happen.
///
/// And it counts only per-entry findings — a dead directory, a duplicate, a stray
/// separator — because those are things a person can go and fix. Shadowing is
/// usually correct and intentional, and `system32` alone guarantees some of it on
/// every Windows machine, so counting it would leave exit 1 permanently on. Anyone
/// who does want it gate-worthy asks with `--fail-on-shadow`.
fn reported_findings(report: &AuditReport, entries: &[&PathEntry], options: &Options) -> bool {
    let actionable =
        !options.shadows_only && entries.iter().any(|entry| !entry.findings.is_empty());

    // `executables` holds every name found, around a thousand of them, so the
    // question is whether any is contested — not whether the list is empty.
    let shadowing = options.fail_on_shadow && report.shadowed().next().is_some();

    actionable || shadowing
}

#[cfg(test)]
mod tests {
    use super::reported_findings;
    use crate::options::Options;
    use clap::Parser;
    use pathdoc_core::{
        AuditReport, Capability, Finding, Occurrence, PathEntry, PathScope, Resolved, ValueKind,
    };

    fn options(args: &[&str]) -> Options {
        match Options::try_parse_from(std::iter::once("pathdoc").chain(args.iter().copied())) {
            Ok(options) => options,
            Err(err) => panic!("parsing {args:?} failed: {err}"),
        }
    }

    fn entry(index: usize, scope: PathScope, findings: Vec<Finding>) -> PathEntry {
        PathEntry {
            index,
            scope,
            raw: r"C:\somewhere".to_owned(),
            expanded: None,
            value_kind: Some(ValueKind::Sz),
            process_position: Some(index),
            findings,
        }
    }

    fn report(entries: Vec<PathEntry>) -> AuditReport {
        AuditReport {
            entries,
            executables: Vec::new(),
            interpreters_consulted: Vec::new(),
            capabilities: vec![Capability::Composition, Capability::EntryFindings],
        }
    }

    fn occurrence(entry_index: usize, file_name: &str) -> Occurrence {
        Occurrence {
            entry_index,
            scope: PathScope::User,
            process_position: Some(entry_index),
            directory: format!(r"C:\place{entry_index}"),
            file_name: file_name.to_owned(),
            is_reparse_point: false,
        }
    }

    fn shadowed_report() -> AuditReport {
        let mut report = report(vec![entry(0, PathScope::Machine, Vec::new())]);
        report.capabilities.push(Capability::ShadowDetection);
        report.executables = vec![Resolved {
            stem: "git".to_owned(),
            intercepts: Vec::new(),
            occurrences: vec![occurrence(0, "git.exe"), occurrence(1, "git.exe")],
        }];
        report
    }

    #[test]
    fn a_clean_report_exits_clean() {
        let report = report(vec![entry(0, PathScope::Machine, Vec::new())]);
        let entries: Vec<&PathEntry> = report.entries.iter().collect();

        assert!(!reported_findings(&report, &entries, &options(&[])));
    }

    #[test]
    fn an_actionable_finding_in_the_reported_scope_counts() {
        let report = report(vec![entry(0, PathScope::User, vec![Finding::Missing])]);
        let entries: Vec<&PathEntry> = report.entries.iter().collect();

        assert!(reported_findings(&report, &entries, &options(&[])));
    }

    #[test]
    fn every_per_entry_finding_is_treated_as_actionable() {
        // All six are things a person can go and fix, which is the line drawn here.
        for finding in [
            Finding::Missing,
            Finding::NotADirectory,
            Finding::Duplicate { first_seen_at: 0 },
            Finding::Empty,
            Finding::Relative,
            Finding::Unreadable,
        ] {
            let report = report(vec![entry(0, PathScope::User, vec![finding.clone()])]);
            let entries: Vec<&PathEntry> = report.entries.iter().collect();

            assert!(
                reported_findings(&report, &entries, &options(&[])),
                "{finding:?} should fail the run"
            );
        }
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

        assert!(!reported_findings(&report, &entries, &options(&[])));
    }

    #[test]
    fn a_name_that_resolves_uniquely_is_not_a_finding() {
        // The trap this guards: `executables` is never empty on a real machine, so
        // testing it for emptiness would make every run exit non-zero.
        let mut clean = report(vec![entry(0, PathScope::Machine, Vec::new())]);
        clean.capabilities.push(Capability::ShadowDetection);
        clean.executables = vec![Resolved {
            stem: "gzip".to_owned(),
            intercepts: Vec::new(),
            occurrences: vec![occurrence(0, "gzip.exe")],
        }];
        let entries: Vec<&PathEntry> = clean.entries.iter().collect();

        assert!(!reported_findings(&clean, &entries, &options(&[])));
    }

    #[test]
    fn shadowing_alone_does_not_fail_the_run() {
        // system32 alone guarantees shadowing on any Windows machine, so counting
        // it would leave exit 1 permanently on, and a signal that is always on is
        // not a signal.
        let report = shadowed_report();
        let entries: Vec<&PathEntry> = report.entries.iter().collect();

        assert!(!reported_findings(&report, &entries, &options(&[])));
    }

    #[test]
    fn shadowing_fails_the_run_when_asked_to() {
        let report = shadowed_report();
        let entries: Vec<&PathEntry> = report.entries.iter().collect();

        assert!(reported_findings(
            &report,
            &entries,
            &options(&["--fail-on-shadow"])
        ));
    }

    #[test]
    fn fail_on_shadow_does_not_fire_on_a_name_that_resolves_once() {
        let mut report = report(vec![entry(0, PathScope::Machine, Vec::new())]);
        report.capabilities.push(Capability::ShadowDetection);
        report.executables = vec![Resolved {
            stem: "gzip".to_owned(),
            intercepts: Vec::new(),
            occurrences: vec![occurrence(0, "gzip.exe")],
        }];
        let entries: Vec<&PathEntry> = report.entries.iter().collect();

        assert!(!reported_findings(
            &report,
            &entries,
            &options(&["--fail-on-shadow"])
        ));
    }

    #[test]
    fn shadows_only_takes_entry_findings_off_the_table() {
        let report = report(vec![entry(0, PathScope::User, vec![Finding::Missing])]);
        let entries: Vec<&PathEntry> = report.entries.iter().collect();

        // Not on screen, so it cannot be what failed.
        assert!(!reported_findings(
            &report,
            &entries,
            &options(&["--shadows-only"])
        ));
    }

    #[test]
    fn shadows_only_with_fail_on_shadow_still_fails_on_shadowing() {
        let report = shadowed_report();
        let entries: Vec<&PathEntry> = report.entries.iter().collect();

        assert!(reported_findings(
            &report,
            &entries,
            &options(&["--shadows-only", "--fail-on-shadow"])
        ));
    }
}
