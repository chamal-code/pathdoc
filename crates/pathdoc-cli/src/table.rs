//! The human-readable rendering. Every column width and colour code in the
//! project lives here or in `main`, and none of it in `pathdoc-core`.
//!
//! Styles are written unconditionally and stripped downstream: production wraps
//! stdout in `anstream`, which decides whether the destination can take ANSI, and
//! the tests wrap a buffer in `anstream::StripStream`. One mechanism, so a test
//! reads the same text a user sees.

use std::io::{self, Write};

use anstyle::{AnsiColor, Style};
use pathdoc_core::{AuditReport, Capability, Finding, PathEntry, PathScope, ValueKind};

/// Section titles and column headers.
const HEADING: Style = Style::new().bold();
/// Secondary detail: the stored form, absent values, explanatory notes.
const MUTED: Style = Style::new().dimmed();
/// A finding that means something is broken.
const BROKEN: Style = AnsiColor::Red.on_default();
/// A finding that means something is untidy or ambiguous.
const UNTIDY: Style = AnsiColor::Yellow.on_default();

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
    write_shadows(out, report)
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
    write!(out, "{:<SCOPE_WIDTH$}  ", "SCOPE")?;
    write!(out, "{:<KIND_WIDTH$}  ", "VALUE TYPE")?;
    writeln!(out, "DIRECTORY{}", HEADING.render_reset())?;

    for entry in entries {
        write!(out, "  {:>index_width$}  ", entry.index)?;

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
            let indent = 2 + index_width + 2 + SCOPE_WIDTH + 2 + KIND_WIDTH + 2;
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

/// The shadow section, which for now exists mainly to say it is not built.
fn write_shadows(out: &mut impl Write, report: &AuditReport) -> io::Result<()> {
    if !report.computed(Capability::ShadowDetection) {
        heading(out, "Shadowed executables", "not computed")?;
        return note(
            out,
            "Executable enumeration is not implemented in this build, so the empty\n  \
             result above says nothing about shadowing.",
        );
    }

    heading(
        out,
        "Shadowed executables",
        &report.shadows.len().to_string(),
    )?;

    if report.shadows.is_empty() {
        return note(out, "No executable name resolves from more than one entry.");
    }

    for shadowed in &report.shadows {
        writeln!(
            out,
            "  {}{}{}",
            HEADING.render(),
            shadowed.stem,
            HEADING.render_reset()
        )?;
        for (position, occurrence) in shadowed.occurrences.iter().enumerate() {
            let marker = if position == 0 { "wins  " } else { "hidden" };
            let style = if position == 0 { Style::new() } else { MUTED };
            writeln!(
                out,
                "    {}{marker}{}  #{}  {}{}",
                style.render(),
                style.render_reset(),
                occurrence.entry_index,
                occurrence.file_name,
                if occurrence.is_reparse_point {
                    "  (reparse point)"
                } else {
                    ""
                }
            )?;
        }
    }

    Ok(())
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
    use super::write_report;
    use anstream::StripStream;
    use pathdoc_core::{
        AuditReport, Capability, Finding, Occurrence, PathEntry, PathScope, Shadowed, ValueKind,
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
            findings: Vec::new(),
        }
    }

    fn report(entries: Vec<PathEntry>) -> AuditReport {
        AuditReport {
            entries,
            shadows: Vec::new(),
            capabilities: vec![Capability::Composition, Capability::EntryFindings],
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
        assert!(text.contains("not implemented in this build"));
        // The dangerous wording would be a bare zero.
        assert!(!text.contains("Shadowed executables  (0)"));
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

    #[test]
    fn a_shadowed_stem_names_the_winner_and_the_hidden_copies() {
        let mut computed = report(vec![
            entry(0, PathScope::Machine, r"C:\Program Files\Git\cmd"),
            entry(1, PathScope::User, r"C:\Users\Someone\hermes\git\cmd"),
        ]);
        computed.capabilities.push(Capability::ShadowDetection);
        computed.shadows = vec![Shadowed {
            stem: "git".to_owned(),
            occurrences: vec![
                Occurrence {
                    entry_index: 0,
                    file_name: "git.exe".to_owned(),
                    is_reparse_point: false,
                },
                Occurrence {
                    entry_index: 1,
                    file_name: "git.exe".to_owned(),
                    is_reparse_point: true,
                },
            ],
        }];

        let text = render(&computed, true);

        assert!(text.contains("Shadowed executables  (1)"));
        assert!(text.contains("git"));
        let wins = text.find("wins");
        let hidden = text.find("hidden");
        assert!(wins.is_some() && hidden.is_some());
        assert!(wins < hidden, "the winner is listed first");
        assert!(text.contains("(reparse point)"));
    }

    #[test]
    fn an_empty_scope_is_reported_rather_than_left_blank() {
        let text = render(&report(Vec::new()), false);

        assert!(text.contains("No entries in scope."));
    }
}
