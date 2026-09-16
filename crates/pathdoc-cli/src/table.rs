//! The human-readable rendering. Every column width and colour code in the
//! project lives here or in `main`, and none of it in `pathdoc-core`.
//!
//! Styles are written unconditionally and stripped downstream: production wraps
//! stdout in `anstream`, which decides whether the destination can take ANSI, and
//! the tests wrap a buffer in `anstream::StripStream`. One mechanism, so a test
//! reads the same text a user sees.

use std::io::{self, Write};

use anstyle::{AnsiColor, Style};
use pathdoc_core::{
    AuditReport, Capability, Finding, PathEntry, PathScope, Resolved, ShellConstruct, ValueKind,
};

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

    // Both concerns in one section, because they answer one question: if I type this
    // name, what runs. Splitting them would make a reader join two lists.
    let listed: Vec<&Resolved> = report
        .executables
        .iter()
        .filter(|resolved| resolved.is_shadowed() || resolved.is_intercepted())
        .collect();
    let shadowed = listed.iter().filter(|r| r.is_shadowed()).count();
    let intercepted = listed.iter().filter(|r| r.is_intercepted()).count();

    heading(
        out,
        "Shadowed or intercepted",
        &format!(
            "{shadowed} shadowed, {intercepted} intercepted, of {} names",
            report.executables.len()
        ),
    )?;

    if listed.is_empty() {
        return note(
            out,
            "No executable name resolves from more than one place, and nothing masks one.",
        );
    }

    note(
        out,
        "Ranked as this process resolves them. A copy this process cannot reach is\n  \
         marked unseen, and a name a new shell would resolve differently says so.",
    )?;

    write_masking_note(out, report)?;
    writeln!(out)?;

    // With one interpreter the section note already named it. With several, each
    // intercept has to say which shell it came from or the report is ambiguous.
    let name_the_shell = report.interpreters_consulted.len() > 1;
    for resolved in listed {
        write_stem(out, resolved, name_the_shell)?;
    }

    Ok(())
}

/// The interpreter's file name, which is enough to tell two apart on one line.
fn shell_label(interpreter: &str) -> &str {
    interpreter
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(interpreter)
}

/// One name: what intercepts it, then every file that answers to it.
fn write_stem(out: &mut impl Write, resolved: &Resolved, name_the_shell: bool) -> io::Result<()> {
    write!(
        out,
        "  {}{}{}",
        HEADING.render(),
        resolved.stem,
        HEADING.render_reset()
    )?;
    if resolved.is_pathext_only() {
        // Worth saying, because reordering PATH will not change this and people
        // reliably expect it to.
        write!(
            out,
            "  {}one directory, decided by PATHEXT order{}",
            MUTED.render(),
            MUTED.render_reset()
        )?;
    }
    writeln!(out)?;

    // Before the files, because these win before PATH is consulted at all.
    for intercept in &resolved.intercepts {
        let construct = match intercept.construct {
            ShellConstruct::Alias => "alias",
            ShellConstruct::Function => "function",
        };
        let target = intercept
            .resolves_to
            .as_deref()
            .map_or_else(String::new, |to| format!(" -> {to}"));
        // The interpreter is named per line only when more than one was asked;
        // otherwise the section note already said which, and repeating an absolute
        // path on every line buries the finding.
        let shell = if name_the_shell {
            format!("  in {}", shell_label(&intercept.interpreter))
        } else {
            String::new()
        };
        writeln!(
            out,
            "    {}intercept  {construct}{target}{shell}{}",
            UNTIDY.render(),
            UNTIDY.render_reset()
        )?;
    }

    // Occurrences arrive in live resolution order, so the live winner is the first
    // one the running process can actually reach.
    let live_winner = resolved
        .occurrences
        .iter()
        .position(|occurrence| occurrence.process_position.is_some());

    for (position, occurrence) in resolved.occurrences.iter().enumerate() {
        let (marker, style) = if Some(position) == live_winner {
            ("wins  ", Style::new())
        } else if occurrence.process_position.is_none() {
            // On PATH in the registry, but not in this process. It wins nothing until
            // something restarts.
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

    // The case that used to be reported wrongly: runtime injection goes to the front
    // of the live PATH, so a shim can beat a registry entry now and lose to it in a
    // process started from scratch.
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

    Ok(())
}

/// What interception means, and which shell was asked — or that none was.
///
/// The interpreter is stated once here rather than on every intercepted line: it is
/// the same shell for all of them, and repeating an absolute path two dozen times
/// buries the finding. The JSON keeps it per record, where a consumer may be looking
/// at one name in isolation.
fn write_masking_note(out: &mut impl Write, report: &AuditReport) -> io::Result<()> {
    writeln!(out)?;

    if !report.computed(Capability::ShellMasking) {
        return note(
            out,
            "Shell masking was not checked, so an absent `intercept` below means\n  \
             unknown rather than none. Use --shell-scan no-profile.",
        );
    }

    note(
        out,
        "Interception is shell-layer only. It means typing that name in that shell\n  \
         runs something else. Anything spawning a process by PATH search still\n  \
         gets the file below.",
    )?;

    // Every interpreter that answered, not only the ones that masked something. A
    // name absent from an interpreter listed here is clear in it, which is a verdict;
    // absent from this list means nobody asked.
    for interpreter in &report.interpreters_consulted {
        let profile = if interpreter.profile_loaded {
            "user profile loaded"
        } else {
            "no user profile"
        };
        note(
            out,
            &format!("Shell asked: {} ({profile})", interpreter.path),
        )?;
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
        AuditReport, Capability, Finding, Intercept, Interpreter, Occurrence, PathEntry, PathScope,
        Resolved, ShellConstruct, ValueKind,
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
            interpreters_consulted: Vec::new(),
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
            interpreters_consulted: Vec::new(),
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
                intercepts: Vec::new(),
                occurrences: vec![
                    occurrence(0, r"C:\Program Files\Git\cmd", "git.exe"),
                    vendored,
                ],
            }],
        );

        let text = render(&computed, true);

        assert!(text.contains("Shadowed or intercepted  (1 shadowed, 0 intercepted, of 1 names)"));
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
                intercepts: Vec::new(),
                occurrences: vec![occurrence(0, r"C:\Users\Someone\vendored", "gzip.exe")],
            }],
        );

        let text = render(&computed, true);

        assert!(text.contains("Shadowed or intercepted  (0 shadowed, 0 intercepted, of 1 names)"));
        assert!(text.contains("nothing masks one"));
        assert!(!text.contains("gzip"));
    }

    #[test]
    fn a_contest_inside_one_directory_says_pathext_decided_it() {
        let computed = enumerated(
            vec![entry(0, PathScope::Machine, r"C:\WINDOWS\system32")],
            vec![Resolved {
                stem: "powercfg".to_owned(),
                intercepts: Vec::new(),
                occurrences: vec![
                    occurrence(0, r"C:\WINDOWS\system32", "powercfg.exe"),
                    occurrence(0, r"C:\WINDOWS\system32", "powercfg.cpl"),
                ],
            }],
        );

        let text = render(&computed, true);

        assert!(text.contains("one directory, decided by PATHEXT order"));
    }

    /// The interpreter the masking tests pretend to have asked.
    const SHELL: &str = r"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe";

    /// A report from a build that also asked one shell what it masks.
    fn with_masking(entries: Vec<PathEntry>, executables: Vec<Resolved>) -> AuditReport {
        let mut report = enumerated(entries, executables);
        report.capabilities.push(Capability::ShellMasking);
        report.interpreters_consulted = vec![Interpreter {
            path: SHELL.to_owned(),
            profile_loaded: false,
        }];
        report
    }

    fn intercept(construct: ShellConstruct, resolves_to: Option<&str>) -> Intercept {
        intercept_in(SHELL, construct, resolves_to)
    }

    fn intercept_in(
        interpreter: &str,
        construct: ShellConstruct,
        resolves_to: Option<&str>,
    ) -> Intercept {
        Intercept {
            construct,
            resolves_to: resolves_to.map(str::to_owned),
            interpreter: interpreter.to_owned(),
            profile_loaded: false,
        }
    }

    /// One name, masked in whichever interpreters are given.
    fn masked(stem: &str, file_name: &str, intercepts: Vec<Intercept>) -> Resolved {
        Resolved {
            stem: stem.to_owned(),
            intercepts,
            occurrences: vec![occurrence(0, r"C:\WINDOWS\system32", file_name)],
        }
    }

    #[test]
    fn a_masked_name_is_listed_even_when_nothing_shadows_it() {
        // `sc.exe` exists once and is perfectly healthy. The interesting fact is that
        // typing `sc` never reaches it.
        let masked = masked(
            "sc",
            "sc.exe",
            vec![intercept(ShellConstruct::Alias, Some("Set-Content"))],
        );

        let text = render(
            &with_masking(
                vec![entry(0, PathScope::Machine, r"C:\WINDOWS\system32")],
                vec![masked],
            ),
            true,
        );

        assert!(text.contains("(0 shadowed, 1 intercepted, of 1 names)"));
        assert!(text.contains("intercept  alias -> Set-Content"));
        assert!(text.contains(r"C:\WINDOWS\system32\sc.exe"));
    }

    #[test]
    fn the_output_says_interception_is_shell_layer_only() {
        // Without this the report overstates its own conclusion: the file is still
        // perfectly reachable by anything doing a PATH search.
        let masked = masked(
            "where",
            "where.exe",
            vec![intercept(ShellConstruct::Alias, Some("Where-Object"))],
        );

        let text = render(
            &with_masking(
                vec![entry(0, PathScope::Machine, r"C:\WINDOWS\system32")],
                vec![masked],
            ),
            true,
        );

        assert!(text.contains("shell-layer only"));
        assert!(text.contains("spawning a process by PATH search"));
        // And which shell answered, stated once rather than on every line.
        assert!(
            text.contains(
                r"Shell asked: C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe"
            )
        );
        assert!(text.contains("no user profile"));
    }

    #[test]
    fn a_function_is_reported_without_a_target() {
        let masked = masked(
            "more",
            "more.com",
            vec![intercept(ShellConstruct::Function, None)],
        );

        let text = render(
            &with_masking(
                vec![entry(0, PathScope::Machine, r"C:\WINDOWS\system32")],
                vec![masked],
            ),
            true,
        );

        assert!(text.contains("intercept  function"));
        assert!(
            !text.contains("function ->"),
            "a function has nothing to point at"
        );
    }

    #[test]
    fn with_two_shells_asked_each_intercept_names_its_own() {
        // `curl` is the real case: an alias in Windows PowerShell 5.1 and the actual
        // curl.exe in PowerShell 7. With one interpreter the section note is enough;
        // with two, a line that does not say which shell is ambiguous.
        const PWSH: &str = r"C:\Program Files\PowerShell\7\pwsh.exe";
        let mut report = enumerated(
            vec![entry(0, PathScope::Machine, r"C:\WINDOWS\system32")],
            vec![masked(
                "curl",
                "curl.exe",
                vec![intercept_in(
                    SHELL,
                    ShellConstruct::Alias,
                    Some("Invoke-WebRequest"),
                )],
            )],
        );
        report.capabilities.push(Capability::ShellMasking);
        report.interpreters_consulted = vec![
            Interpreter {
                path: SHELL.to_owned(),
                profile_loaded: false,
            },
            Interpreter {
                path: PWSH.to_owned(),
                profile_loaded: false,
            },
        ];

        let text = render(&report, true);

        // Both shells named in the notes, so an absent record is a verdict.
        assert!(text.contains(SHELL));
        assert!(text.contains(PWSH));
        // And the intercept says which one masked it.
        assert!(
            text.contains("intercept  alias -> Invoke-WebRequest  in powershell.exe"),
            "got:\n{text}"
        );
    }

    #[test]
    fn with_one_shell_asked_the_intercept_line_stays_compact() {
        let text = render(
            &with_masking(
                vec![entry(0, PathScope::Machine, r"C:\WINDOWS\system32")],
                vec![masked(
                    "sc",
                    "sc.exe",
                    vec![intercept(ShellConstruct::Alias, Some("Set-Content"))],
                )],
            ),
            true,
        );

        // The note already named the shell; repeating an absolute path on every line
        // would bury the finding.
        assert!(text.contains("intercept  alias -> Set-Content\n"));
    }

    #[test]
    fn an_unchecked_masking_scan_says_unknown_rather_than_none() {
        // Same discipline as the shadow capability: absence of a finding must not be
        // mistaken for absence of the thing.
        let text = render(
            &enumerated(
                vec![entry(0, PathScope::Machine, r"C:\WINDOWS\system32")],
                vec![Resolved {
                    stem: "sc".to_owned(),
                    intercepts: Vec::new(),
                    occurrences: vec![
                        occurrence(0, r"C:\WINDOWS\system32", "sc.exe"),
                        occurrence(1, r"C:\other", "sc.exe"),
                    ],
                }],
            ),
            true,
        );

        assert!(text.contains("Shell masking was not checked"));
        assert!(text.contains("unknown rather than none"));
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
    fn rendered_output_is_ascii_only() {
        // Windows consoles are frequently not UTF-8, so a non-ASCII character in
        // emitted text arrives as mojibake. An em dash in the interception note did
        // exactly that, printing "ΓÇö" on this machine. Doc comments are free to use
        // whatever they like; anything written to a terminal is not.
        let masked = Resolved {
            stem: "sc".to_owned(),
            intercepts: vec![intercept(ShellConstruct::Alias, Some("Set-Content"))],
            occurrences: vec![
                occurrence(0, r"C:\WINDOWS\system32", "sc.exe"),
                occurrence(1, r"C:\other", "sc.exe"),
            ],
        };
        let mut dead = entry(0, PathScope::Machine, r"C:\WINDOWS\system32");
        dead.findings = vec![Finding::Missing, Finding::Empty];

        // Every section, including the notes and the "not computed" branches.
        for report in [
            with_masking(vec![dead.clone()], vec![masked.clone()]),
            enumerated(vec![dead.clone()], vec![masked.clone()]),
            report(vec![dead, unseen_entry(1, PathScope::User, r"C:\gone")]),
        ] {
            for shadows_only in [false, true] {
                let text = render(&report, shadows_only);
                if let Some(offender) = text.chars().find(|c| !c.is_ascii()) {
                    panic!(
                        "rendered {offender:?} (U+{:04X}) in output",
                        offender as u32
                    );
                }
            }
        }
    }

    #[test]
    fn an_empty_scope_is_reported_rather_than_left_blank() {
        let text = render(&report(Vec::new()), false);

        assert!(text.contains("No entries in scope."));
    }
}
