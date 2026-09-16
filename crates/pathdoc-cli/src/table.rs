//! The human-readable rendering. Every column width and colour code in the
//! project lives here or in `main`, and none of it in `pathdoc-core`.
//!
//! Styles are written unconditionally and stripped downstream: production wraps
//! stdout in `anstream`, which decides whether the destination can take ANSI, and
//! the tests wrap a buffer in `anstream::StripStream`. One mechanism, so a test
//! reads the same text a user sees.

use std::io::{self, Write};

use anstyle::{AnsiColor, Style};
use pathdoc_core::{AuditReport, Capability, Finding, PathEntry, PathScope, Resolved, ValueKind};

/// Section titles and column headers.
const HEADING: Style = Style::new().bold();
/// Secondary detail: the stored form, absent values, explanatory notes.
const MUTED: Style = Style::new().dimmed();
/// A finding that means something is broken.
const BROKEN: Style = AnsiColor::Red.on_default();
/// A finding that means something is untidy or ambiguous.
const UNTIDY: Style = AnsiColor::Yellow.on_default();

/// Width of the `LIVE` column, which holds a small number or a dash.
const LIVE_WIDTH: usize = 4;
/// Width of the widest scope label, `process-only`.
const SCOPE_WIDTH: usize = 12;
/// Width of the widest value type label, `REG_EXPAND_SZ`.
const KIND_WIDTH: usize = 13;
/// Minimum width of the index column, so the `IDX` header fits.
const MIN_INDEX_WIDTH: usize = 3;

/// Write the whole report.
///
/// `entries` is already filtered by `--scope`; `report` is passed whole because
/// the shadow section needs the capability list, which describes the run rather
/// than the filtered view.
pub(crate) fn write_report(
    out: &mut impl Write,
    report: &AuditReport,
    entries: &[&PathEntry],
    shadows_only: bool,
) -> io::Result<()> {
    if !shadows_only {
        write_composition(out, entries)?;
        write_findings(out, entries)?;
    }
    write_executables(out, report)
}

/// The ordered composition table.
fn write_composition(out: &mut impl Write, entries: &[&PathEntry]) -> io::Result<()> {
    let machine = count(entries, PathScope::Machine);
    let user = count(entries, PathScope::User);
    let injected = count(entries, PathScope::ProcessOnly);

    heading(
        out,
        "PATH composition",
        &format!("{machine} machine, {user} user, {injected} injected at runtime"),
    )?;

    if entries.is_empty() {
        return note(out, "No entries in scope.");
    }

    let index_width = index_width(entries);
    write!(out, "  {}", HEADING.render())?;
    write!(out, "{:>index_width$}  ", "IDX")?;
    write!(out, "{:>LIVE_WIDTH$}  ", "LIVE")?;
    write!(out, "{:<SCOPE_WIDTH$}  ", "SCOPE")?;
    write!(out, "{:<KIND_WIDTH$}  ", "VALUE TYPE")?;
    writeln!(out, "DIRECTORY{}", HEADING.render_reset())?;

    for entry in entries {
        write!(out, "  {:>index_width$}  ", entry.index)?;

        // Position in this process's PATH, which is what decides what runs now.
        // A dash means the running process cannot see this directory at all.
        match entry.process_position {
            Some(position) => write!(out, "{position:>LIVE_WIDTH$}  ")?,
            None => write!(
                out,
                "{}{:>LIVE_WIDTH$}{}  ",
                MUTED.render(),
                "-",
                MUTED.render_reset()
            )?,
        }

        let scope = scope_label(entry.scope);
        match entry.scope {
            // Injected at runtime, so a shade quieter than a registry entry.
            PathScope::ProcessOnly => write!(
                out,
                "{}{scope:<SCOPE_WIDTH$}{}  ",
                MUTED.render(),
                MUTED.render_reset()
            )?,
            _ => write!(out, "{scope:<SCOPE_WIDTH$}  ")?,
        }

        match entry.value_kind {
            Some(kind) => write!(out, "{:<KIND_WIDTH$}  ", kind_label(kind))?,
            None => write!(
                out,
                "{}{:<KIND_WIDTH$}{}  ",
                MUTED.render(),
                "-",
                MUTED.render_reset()
            )?,
        }

        writeln!(out, "{}", entry.effective())?;

        // The stored form is a separate fact and only shown when it differs.
        if entry.expanded.is_some() {
            let indent = 2 + index_width + 2 + LIVE_WIDTH + 2 + SCOPE_WIDTH + 2 + KIND_WIDTH + 2;
            writeln!(
                out,
                "{:indent$}{}stored as {}{}",
                "",
                MUTED.render(),
                entry.raw,
                MUTED.render_reset()
            )?;
        }
    }

    // A registry entry with no live position is one this process was started too
    // early to see. Worth saying, because the fix is "restart your shell" and
    // nothing else in the report hints at it.
    let unseen = entries
        .iter()
        .filter(|entry| entry.scope != PathScope::ProcessOnly && !entry.is_live())
        .count();
    if unseen > 0 {
        writeln!(out)?;
        note(
            out,
            &format!(
                "{unseen} entr{} on PATH in the registry but not in this process. \
                 Restart the shell to pick {} up.",
                if unseen == 1 { "y is" } else { "ies are" },
                if unseen == 1 { "it" } else { "them" }
            ),
        )?;
    }

    Ok(())
}

/// Only the entries with something wrong with them.
fn write_findings(out: &mut impl Write, entries: &[&PathEntry]) -> io::Result<()> {
    let flagged: Vec<&&PathEntry> = entries
        .iter()
        .filter(|entry| !entry.findings.is_empty())
        .collect();

    let total: usize = flagged.iter().map(|entry| entry.findings.len()).sum();
    heading(out, "Findings", &total.to_string())?;

    if flagged.is_empty() {
        return note(out, "Nothing to report.");
    }

    let index_width = index_width(entries);
    let label_width = flagged
        .iter()
        .flat_map(|entry| entry.findings.iter())
        .map(|finding| finding_label(finding).len())
        .max()
        .unwrap_or(0);

    for entry in flagged {
        for finding in &entry.findings {
            let label = finding_label(finding);
            let style = finding_style(finding);
            write!(out, "  {:>index_width$}  ", entry.index)?;
            write!(
                out,
                "{}{label:<label_width$}{}  ",
                style.render(),
                style.render_reset()
            )?;
            writeln!(out, "{}", entry.effective())?;
        }
    }

    Ok(())
}

/// The contested names, and a count of how many resolved uniquely.
///
/// Only the contested ones. Every name found is in `--json`, but there are around
/// a thousand of them on an ordinary machine and a thousand-row table helps nobody.
fn write_executables(out: &mut impl Write, report: &AuditReport) -> io::Result<()> {
    if !report.computed(Capability::ShadowDetection) {
        heading(out, "Shadowed executables", "not computed")?;
        return note(
            out,
            "Executable enumeration did not run, so the empty result above says\n  \
             nothing about shadowing.",
        );
    }

    let shadowed: Vec<&Resolved> = report.shadowed().collect();
    heading(
        out,
        "Shadowed executables",
        &format!("{} of {} names", shadowed.len(), report.executables.len()),
    )?;

    if shadowed.is_empty() {
        return note(out, "No executable name resolves from more than one place.");
    }

    note(
        out,
        "Ranked as this process resolves them. A copy this process cannot reach is\n  \
         marked unseen, and a name a new shell would resolve differently says so.",
    )?;
    writeln!(out)?;

    for resolved in shadowed {
        write!(
            out,
            "  {}{}{}",
            HEADING.render(),
            resolved.stem,
            HEADING.render_reset()
        )?;
        if resolved.is_pathext_only() {
            // Worth saying, because reordering PATH will not change this and
            // people reliably expect it to.
            write!(
                out,
                "  {}one directory, decided by PATHEXT order{}",
                MUTED.render(),
                MUTED.render_reset()
            )?;
        }
        writeln!(out)?;

        // Occurrences arrive in live resolution order, so the live winner is the
        // first one the running process can actually reach.
        let live_winner = resolved
            .occurrences
            .iter()
            .position(|occurrence| occurrence.process_position.is_some());

        for (position, occurrence) in resolved.occurrences.iter().enumerate() {
            let (marker, style) = if Some(position) == live_winner {
                ("wins  ", Style::new())
            } else if occurrence.process_position.is_none() {
                // On PATH in the registry, but not in this process. It wins nothing
                // until something restarts.
                ("unseen", MUTED)
            } else {
                ("hidden", MUTED)
            };

            writeln!(
                out,
                "    {}{marker}  #{:<3} {}{}{}",
                style.render(),
                occurrence.entry_index,
                join(&occurrence.directory, &occurrence.file_name),
                if occurrence.is_reparse_point {
                    "  (reparse point, not followed)"
                } else {
                    ""
                },
                style.render_reset()
            )?;
        }

        // The case that used to be reported wrongly: runtime injection goes to the
        // front of the live PATH, so a shim can beat a registry entry now and lose
        // to it in a process started from scratch.
        if resolved.winner_depends_on_context()
            && let Some(fresh) = resolved.fresh_winner()
        {
            writeln!(
                out,
                "    {}note    a new process would run {}{}",
                MUTED.render(),
                join(&fresh.directory, &fresh.file_name),
                MUTED.render_reset()
            )?;
        }
    }

    Ok(())
}

/// Join a directory and a file name, tolerating a directory that already ends in a
/// separator — `%SYSTEMROOT%\System32\OpenSSH\` on this machine does.
fn join(directory: &str, file_name: &str) -> String {
    if directory.ends_with('\\') || directory.ends_with('/') {
        format!("{directory}{file_name}")
    } else {
        format!("{directory}\\{file_name}")
    }
}

/// A blank line, then a bold section title with a parenthesised summary.
fn heading(out: &mut impl Write, title: &str, summary: &str) -> io::Result<()> {
    writeln!(out)?;
    writeln!(
        out,
        "{}{title}{}  ({summary})",
        HEADING.render(),
        HEADING.render_reset()
    )?;
    writeln!(out)
}

/// An indented, muted line for when a section has nothing in it.
fn note(out: &mut impl Write, text: &str) -> io::Result<()> {
    writeln!(out, "  {}{text}{}", MUTED.render(), MUTED.render_reset())
}

fn count(entries: &[&PathEntry], scope: PathScope) -> usize {
    entries.iter().filter(|entry| entry.scope == scope).count()
}

/// Wide enough for the largest index present, but never narrower than the header.
fn index_width(entries: &[&PathEntry]) -> usize {
    entries
        .iter()
        .map(|entry| decimal_width(entry.index))
        .max()
        .unwrap_or(1)
        .max(MIN_INDEX_WIDTH)
}

fn decimal_width(value: usize) -> usize {
    let mut width = 1;
    let mut remaining = value;
    while remaining >= 10 {
        remaining /= 10;
        width += 1;
    }
    width
}

fn scope_label(scope: PathScope) -> &'static str {
    match scope {
        PathScope::Machine => "machine",
        PathScope::User => "user",
        PathScope::ProcessOnly => "process-only",
    }
}

/// The registry type names, rather than a prettified version of them. Somebody
/// reading this output is likely to be looking at `regedit` at the same time.
fn kind_label(kind: ValueKind) -> &'static str {
    match kind {
        ValueKind::Sz => "REG_SZ",
        ValueKind::ExpandSz => "REG_EXPAND_SZ",
    }
}

fn finding_label(finding: &Finding) -> String {
    match finding {
        Finding::Missing => "missing".to_owned(),
        Finding::NotADirectory => "not a directory".to_owned(),
        Finding::Duplicate { first_seen_at } => format!("duplicate of #{first_seen_at}"),
        Finding::Empty => "empty segment".to_owned(),
        Finding::Relative => "relative".to_owned(),
        Finding::Unreadable => "unreadable".to_owned(),
    }
}

/// Broken versus untidy. A missing directory is a defect; a duplicate is noise.
fn finding_style(finding: &Finding) -> Style {
    match finding {
        Finding::Missing | Finding::NotADirectory | Finding::Unreadable => BROKEN,
        Finding::Duplicate { .. } | Finding::Empty | Finding::Relative => UNTIDY,
    }
}

#[cfg(test)]
mod tests {
    use super::{join, write_report};
    use anstream::StripStream;
    use pathdoc_core::{
        AuditReport, Capability, Finding, Occurrence, PathEntry, PathScope, Resolved, ValueKind,
    };

    /// Renders with the ANSI stripped, so assertions read like the output does.
    fn render(report: &AuditReport, shadows_only: bool) -> String {
        let entries: Vec<&PathEntry> = report.entries.iter().collect();
        let mut buffer = Vec::new();
        {
            let mut stream = StripStream::new(&mut buffer);
            if let Err(err) = write_report(&mut stream, report, &entries, shadows_only) {
                panic!("rendering failed: {err}");
            }
        }
        match String::from_utf8(buffer) {
            Ok(text) => text,
            Err(err) => panic!("output was not utf-8: {err}"),
        }
    }

    fn entry(index: usize, scope: PathScope, raw: &str) -> PathEntry {
        PathEntry {
            index,
            scope,
            raw: raw.to_owned(),
            expanded: None,
            value_kind: Some(ValueKind::ExpandSz),
            process_position: Some(index),
            findings: Vec::new(),
        }
    }

    /// An entry the running process cannot see: added to the registry after it
    /// started.
    fn unseen_entry(index: usize, scope: PathScope, raw: &str) -> PathEntry {
        let mut entry = entry(index, scope, raw);
        entry.process_position = None;
        entry
    }

    /// A report from a build without shadow detection.
    fn report(entries: Vec<PathEntry>) -> AuditReport {
        AuditReport {
            entries,
            executables: Vec::new(),
            capabilities: vec![Capability::Composition, Capability::EntryFindings],
        }
    }

    fn occurrence(entry_index: usize, directory: &str, file_name: &str) -> Occurrence {
        Occurrence {
            entry_index,
            scope: PathScope::Machine,
            process_position: Some(entry_index),
            directory: directory.to_owned(),
            file_name: file_name.to_owned(),
            is_reparse_point: false,
        }
    }

    #[test]
    fn the_table_lists_entries_in_composed_order() {
        let text = render(
            &report(vec![
                entry(0, PathScope::Machine, r"C:\WINDOWS\system32"),
                entry(1, PathScope::User, r"C:\Users\Someone\.cargo\bin"),
            ]),
            false,
        );

        let system32 = text.find(r"C:\WINDOWS\system32");
        let cargo = text.find(r"C:\Users\Someone\.cargo\bin");
        assert!(system32.is_some() && cargo.is_some());
        assert!(system32 < cargo, "machine entry must be rendered first");
        assert!(text.contains("1 machine, 1 user, 0 injected at runtime"));
        assert!(text.contains("REG_EXPAND_SZ"));
    }

    #[test]
    fn the_stored_form_is_shown_only_when_it_differs() {
        let mut expanded = entry(0, PathScope::Machine, r"%SystemRoot%\system32");
        expanded.expanded = Some(r"C:\WINDOWS\system32".to_owned());
        let plain = entry(1, PathScope::Machine, r"C:\Program Files\Git\cmd");

        let text = render(&report(vec![expanded, plain]), false);

        assert!(text.contains(r"stored as %SystemRoot%\system32"));
        assert_eq!(text.matches("stored as").count(), 1);
    }

    #[test]
    fn an_entry_the_process_cannot_see_is_called_out_with_a_restart_hint() {
        // The fix is "restart your shell" and nothing else in the report hints at
        // it, so the table has to say so.
        let text = render(
            &report(vec![
                entry(0, PathScope::Machine, r"C:\WINDOWS\system32"),
                unseen_entry(1, PathScope::Machine, r"C:\Program Files\GitHub CLI\"),
            ]),
            false,
        );

        assert!(text.contains("LIVE"), "the live position column is missing");
        assert!(text.contains("1 entry is on PATH in the registry but not in this process"));
        assert!(text.contains("Restart the shell to pick it up."));
    }

    #[test]
    fn entries_the_process_can_all_see_get_no_restart_hint() {
        let text = render(
            &report(vec![entry(0, PathScope::Machine, r"C:\WINDOWS\system32")]),
            false,
        );

        assert!(!text.contains("Restart the shell"));
    }

    #[test]
    fn a_process_only_entry_shows_a_dash_for_its_value_type() {
        let mut injected = entry(0, PathScope::ProcessOnly, r"C:\shim");
        injected.value_kind = None;

        let text = render(&report(vec![injected]), false);

        assert!(text.contains("process-only"));
        assert!(text.contains("0 machine, 0 user, 1 injected at runtime"));
    }

    #[test]
    fn findings_are_listed_with_the_index_they_belong_to() {
        let mut dead = entry(3, PathScope::User, r"C:\Users\Someone\nope");
        dead.findings = vec![Finding::Missing];
        let mut messy = entry(4, PathScope::User, r"C:\Users\Someone\again");
        messy.findings = vec![Finding::Relative, Finding::Duplicate { first_seen_at: 3 }];

        let text = render(&report(vec![dead, messy]), false);

        assert!(text.contains("Findings  (3)"));
        assert!(text.contains("missing"));
        assert!(text.contains("relative"));
        assert!(text.contains("duplicate of #3"));
    }

    #[test]
    fn a_clean_path_says_so() {
        let text = render(
            &report(vec![entry(0, PathScope::Machine, r"C:\WINDOWS")]),
            false,
        );

        assert!(text.contains("Findings  (0)"));
        assert!(text.contains("Nothing to report."));
    }

    #[test]
    fn an_uncomputed_shadow_section_refuses_to_look_clean() {
        let text = render(
            &report(vec![entry(0, PathScope::Machine, r"C:\WINDOWS")]),
            false,
        );

        assert!(text.contains("Shadowed executables  (not computed)"));
        assert!(text.contains("did not run"));
        // The dangerous wording would be a bare zero.
        assert!(!text.contains("Shadowed executables  (0"));
    }

    #[test]
    fn shadows_only_omits_the_composition_and_findings() {
        let mut dead = entry(0, PathScope::User, r"C:\Users\Someone\nope");
        dead.findings = vec![Finding::Missing];

        let text = render(&report(vec![dead]), true);

        assert!(!text.contains("PATH composition"));
        assert!(!text.contains("Findings"));
        assert!(text.contains("Shadowed executables"));
    }

    /// A report from a build that did enumerate.
    fn enumerated(entries: Vec<PathEntry>, executables: Vec<Resolved>) -> AuditReport {
        AuditReport {
            entries,
            executables,
            capabilities: vec![
                Capability::Composition,
                Capability::EntryFindings,
                Capability::ShadowDetection,
            ],
        }
    }

    #[test]
    fn a_shadowed_stem_names_the_winner_and_the_hidden_copies() {
        let mut vendored = occurrence(1, r"C:\Users\Someone\hermes\git\cmd", "git.exe");
        vendored.is_reparse_point = true;
        let computed = enumerated(
            vec![
                entry(0, PathScope::Machine, r"C:\Program Files\Git\cmd"),
                entry(1, PathScope::User, r"C:\Users\Someone\hermes\git\cmd"),
            ],
            vec![Resolved {
                stem: "git".to_owned(),
                occurrences: vec![
                    occurrence(0, r"C:\Program Files\Git\cmd", "git.exe"),
                    vendored,
                ],
            }],
        );

        let text = render(&computed, true);

        assert!(text.contains("Shadowed executables  (1 of 1 names)"));
        // The full path, not just the file name, so it can be acted on.
        assert!(text.contains(r"C:\Program Files\Git\cmd\git.exe"));
        let wins = text.find("wins");
        let hidden = text.find("hidden");
        assert!(wins.is_some() && hidden.is_some());
        assert!(wins < hidden, "the winner is listed first");
        assert!(text.contains("reparse point, not followed"));
    }

    #[test]
    fn a_name_that_resolves_uniquely_is_counted_but_not_listed() {
        // Around a thousand of these on a real machine, so the table counts them
        // and `--json` carries them.
        let computed = enumerated(
            vec![entry(0, PathScope::User, r"C:\Users\Someone\vendored")],
            vec![Resolved {
                stem: "gzip".to_owned(),
                occurrences: vec![occurrence(0, r"C:\Users\Someone\vendored", "gzip.exe")],
            }],
        );

        let text = render(&computed, true);

        assert!(text.contains("Shadowed executables  (0 of 1 names)"));
        assert!(text.contains("No executable name resolves from more than one place."));
        assert!(!text.contains("gzip"));
    }

    #[test]
    fn a_contest_inside_one_directory_says_pathext_decided_it() {
        let computed = enumerated(
            vec![entry(0, PathScope::Machine, r"C:\WINDOWS\system32")],
            vec![Resolved {
                stem: "powercfg".to_owned(),
                occurrences: vec![
                    occurrence(0, r"C:\WINDOWS\system32", "powercfg.exe"),
                    occurrence(0, r"C:\WINDOWS\system32", "powercfg.cpl"),
                ],
            }],
        );

        let text = render(&computed, true);

        assert!(text.contains("one directory, decided by PATHEXT order"));
    }

    #[test]
    fn a_directory_that_already_ends_in_a_separator_is_not_doubled() {
        assert_eq!(
            join(r"C:\WINDOWS\System32\OpenSSH\", "ssh.exe"),
            r"C:\WINDOWS\System32\OpenSSH\ssh.exe"
        );
        assert_eq!(
            join(r"C:\Program Files\Git\cmd", "git.exe"),
            r"C:\Program Files\Git\cmd\git.exe"
        );
    }

    #[test]
    fn an_empty_scope_is_reported_rather_than_left_blank() {
        let text = render(&report(Vec::new()), false);

        assert!(text.contains("No entries in scope."));
    }
}
