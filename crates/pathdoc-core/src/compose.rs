//! Turning stored `PATH` text into the ordered entry list Windows resolves.
//!
//! Windows composes the effective `PATH` as **machine entries first, then user
//! entries**. Getting that backwards inverts every later verdict about which
//! copy of a program wins, so it is the one thing this module exists to get
//! right.
//!
//! Everything here is pure. No registry, no filesystem, and no environment
//! access except through an injected lookup, which keeps the tests portable and
//! keeps any single machine's `PATH` layout out of the logic.

use std::borrow::Cow;
use std::collections::HashMap;
use std::collections::hash_map::Entry;

use crate::registry::ScopeValue;
use crate::{Finding, PathEntry, PathScope, ValueKind};

/// Windows separates `PATH` entries with a semicolon.
const SEPARATOR: char = ';';

/// A quoted segment may legally contain a separator.
const QUOTE: char = '"';

/// Delimits an environment reference inside a `REG_EXPAND_SZ` value.
const PERCENT: char = '%';

/// Compose the ordered entry list.
///
/// Registry entries come first, machine before user, and take indices `0..n`.
/// Any directory found in `process` but in neither registry scope is appended
/// after them as [`PathScope::ProcessOnly`]. Appending rather than interleaving
/// is deliberate: the registry order is the composition Windows would build for
/// a fresh process, and runtime injection is a separate fact layered on top.
pub(crate) fn compose<F>(
    machine: Option<&ScopeValue>,
    user: Option<&ScopeValue>,
    process: Option<&str>,
    lookup: &F,
) -> Vec<PathEntry>
where
    F: Fn(&str) -> Option<String>,
{
    let mut entries: Vec<PathEntry> = Vec::new();
    let mut seen: HashMap<String, usize> = HashMap::new();

    for (scope, value) in [(PathScope::Machine, machine), (PathScope::User, user)] {
        let Some(value) = value else { continue };
        for segment in split_segments(&value.text) {
            let effective = resolve(segment, Some(value.kind), lookup);
            let entry = build(
                entries.len(),
                scope,
                Some(value.kind),
                segment,
                effective,
                &mut seen,
            );
            entries.push(entry);
        }
    }

    if let Some(process) = process {
        for segment in split_segments(process) {
            // The process block is already expanded, so no value kind applies
            // and no expansion is attempted.
            let effective = resolve(segment, None, lookup);
            // A stray separator in the live block tells us nothing about the
            // registry, and the process block is only being mined here for
            // directories the registry does not mention.
            if effective.is_empty() || seen.contains_key(&canonical_key(&effective)) {
                continue;
            }
            let entry = build(
                entries.len(),
                PathScope::ProcessOnly,
                None,
                segment,
                effective,
                &mut seen,
            );
            entries.push(entry);
        }
    }

    entries
}

/// Build one entry and record the order-dependent findings for it.
///
/// Findings that depend on the filesystem are added later, by `probe`, so this
/// stays pure.
fn build(
    index: usize,
    scope: PathScope,
    value_kind: Option<ValueKind>,
    raw: &str,
    effective: String,
    seen: &mut HashMap<String, usize>,
) -> PathEntry {
    let mut findings = Vec::new();

    if effective.is_empty() {
        findings.push(Finding::Empty);
    } else {
        if !is_absolute(&effective) {
            findings.push(Finding::Relative);
        }
        match seen.entry(canonical_key(&effective)) {
            Entry::Occupied(occupied) => findings.push(Finding::Duplicate {
                first_seen_at: *occupied.get(),
            }),
            Entry::Vacant(vacant) => {
                vacant.insert(index);
            }
        }
    }

    let expanded = if effective == raw {
        None
    } else {
        Some(effective)
    };

    PathEntry {
        index,
        scope,
        raw: raw.to_owned(),
        expanded,
        value_kind,
        findings,
    }
}

/// Split a `PATH` value on unquoted separators.
///
/// An empty value contributes no entries at all. An empty *segment* inside a
/// non-empty value is kept, because a stray `;` is a real finding.
fn split_segments(text: &str) -> Vec<&str> {
    if text.is_empty() {
        return Vec::new();
    }

    let mut segments = Vec::new();
    let mut start = 0usize;
    let mut quoted = false;

    for (offset, character) in text.char_indices() {
        match character {
            QUOTE => quoted = !quoted,
            SEPARATOR if !quoted => {
                segments.push(&text[start..offset]);
                start = offset + character.len_utf8();
            }
            _ => {}
        }
    }
    segments.push(&text[start..]);

    segments
}

/// The value Windows would actually resolve for one stored segment.
///
/// Expansion happens only for `REG_EXPAND_SZ`. A `REG_SZ` holding `%FOO%\bin`
/// is a literal directory name with percent signs in it, and reporting it as
/// though it resolved would be a lie. Surrounding whitespace and one layer of
/// surrounding quotes are removed, since neither is part of the directory name.
fn resolve<F>(raw: &str, kind: Option<ValueKind>, lookup: &F) -> String
where
    F: Fn(&str) -> Option<String>,
{
    let expanded: Cow<'_, str> = if matches!(kind, Some(ValueKind::ExpandSz)) {
        Cow::Owned(expand(raw, lookup))
    } else {
        Cow::Borrowed(raw)
    };

    unwrap_quotes(&expanded).to_owned()
}

/// Substitute `%NAME%` references, leaving anything unresolved verbatim.
///
/// Matches what `ExpandEnvironmentStrings` does with the cases that matter: an
/// undefined name keeps its percent signs, and a lone `%` is just a character.
fn expand<F>(raw: &str, lookup: &F) -> String
where
    F: Fn(&str) -> Option<String>,
{
    if !raw.contains(PERCENT) {
        return raw.to_owned();
    }

    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;

    while let Some(open) = rest.find(PERCENT) {
        out.push_str(&rest[..open]);
        let after = &rest[open + PERCENT.len_utf8()..];

        let Some(close) = after.find(PERCENT) else {
            // Unpaired: the rest of the value is literal.
            out.push(PERCENT);
            out.push_str(after);
            return out;
        };

        let name = &after[..close];
        match lookup(name) {
            Some(value) if !name.is_empty() => out.push_str(&value),
            _ => {
                out.push(PERCENT);
                out.push_str(name);
                out.push(PERCENT);
            }
        }
        rest = &after[close + PERCENT.len_utf8()..];
    }
    out.push_str(rest);

    out
}

/// Trim whitespace and strip one matched pair of surrounding quotes.
fn unwrap_quotes(value: &str) -> &str {
    let trimmed = value.trim();
    trimmed
        .strip_prefix(QUOTE)
        .and_then(|inner| inner.strip_suffix(QUOTE))
        .unwrap_or(trimmed)
        .trim()
}

/// Key used to decide whether two entries name the same directory.
///
/// Textual on purpose. `std::fs::canonicalize` would follow reparse points and
/// fail outright on a directory that does not exist, and both of those are facts
/// this tool needs to keep reporting rather than resolve away.
fn canonical_key(effective: &str) -> String {
    let trimmed = effective.trim_end_matches(['\\', '/']);
    // `C:\` must not collapse to `C:`; drive-relative and drive-root are
    // genuinely different locations.
    if trimmed.is_empty() || trimmed.ends_with(':') {
        effective.to_lowercase()
    } else {
        trimmed.to_lowercase()
    }
}

/// Whether a `PATH` entry is absolute by Windows' rules.
///
/// Spelled out rather than delegated to [`std::path::Path::is_absolute`] so the
/// answer does not change with the host platform. Note that `\bin` is rooted but
/// drive-relative, and `C:bin` is relative to the drive's current directory, so
/// neither is absolute.
fn is_absolute(value: &str) -> bool {
    let bytes = value.as_bytes();

    // UNC (`\\server\share`) and extended-length (`\\?\C:\...`) prefixes.
    if bytes.len() >= 2 && matches!(bytes[0], b'\\' | b'/') && matches!(bytes[1], b'\\' | b'/') {
        return true;
    }

    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/')
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_key, compose, expand, is_absolute, resolve, split_segments, unwrap_quotes,
    };
    use crate::registry::ScopeValue;
    use crate::{Finding, PathScope, ValueKind};

    /// Nothing here depends on the machine the tests run on. Every input is
    /// supplied explicitly, including the environment lookup.
    fn no_vars(_: &str) -> Option<String> {
        None
    }

    fn vars(name: &str) -> Option<String> {
        match name {
            "SystemRoot" => Some(r"C:\WINDOWS".to_owned()),
            "USERPROFILE" => Some(r"C:\Users\Someone".to_owned()),
            _ => None,
        }
    }

    fn scope(text: &str, kind: ValueKind) -> ScopeValue {
        ScopeValue {
            text: text.to_owned(),
            kind,
        }
    }

    #[test]
    fn an_empty_value_contributes_no_entries() {
        assert!(split_segments("").is_empty());
    }

    #[test]
    fn segments_split_on_semicolons() {
        assert_eq!(
            split_segments(r"C:\one;C:\two;C:\three"),
            vec![r"C:\one", r"C:\two", r"C:\three"]
        );
    }

    #[test]
    fn a_trailing_separator_leaves_an_empty_segment() {
        assert_eq!(split_segments(r"C:\one;"), vec![r"C:\one", ""]);
        assert_eq!(split_segments(r";C:\one"), vec!["", r"C:\one"]);
        assert_eq!(
            split_segments(r"C:\one;;C:\two"),
            vec![r"C:\one", "", r"C:\two"]
        );
    }

    #[test]
    fn a_quoted_segment_may_contain_a_separator() {
        assert_eq!(
            split_segments(r#"C:\one;"C:\two;still two";C:\three"#),
            vec![r"C:\one", r#""C:\two;still two""#, r"C:\three"]
        );
    }

    #[test]
    fn quotes_and_padding_are_not_part_of_the_directory_name() {
        assert_eq!(unwrap_quotes(r#"  "C:\one"  "#), r"C:\one");
        assert_eq!(unwrap_quotes(r"  C:\one  "), r"C:\one");
        // A lone quote is not a matched pair and is left alone.
        assert_eq!(unwrap_quotes(r#""C:\one"#), r#""C:\one"#);
    }

    #[test]
    fn expansion_substitutes_known_names() {
        assert_eq!(
            expand(r"%SystemRoot%\system32", &vars),
            r"C:\WINDOWS\system32"
        );
    }

    #[test]
    fn expansion_leaves_unknown_names_verbatim() {
        assert_eq!(expand(r"%NOPE%\bin", &vars), r"%NOPE%\bin");
        assert_eq!(expand(r"%%", &vars), "%%");
        assert_eq!(expand(r"C:\100% effort", &no_vars), r"C:\100% effort");
        assert_eq!(expand(r"C:\plain", &no_vars), r"C:\plain");
    }

    #[test]
    fn expansion_handles_adjacent_references() {
        assert_eq!(
            expand("%SystemRoot%%SystemRoot%", &vars),
            r"C:\WINDOWSC:\WINDOWS"
        );
    }

    #[test]
    fn reg_sz_is_never_expanded() {
        // The whole point of recording the value kind: a literal percent sign in
        // a REG_SZ is part of the directory name.
        assert_eq!(
            resolve(r"%SystemRoot%\system32", Some(ValueKind::Sz), &vars),
            r"%SystemRoot%\system32"
        );
        assert_eq!(
            resolve(r"%SystemRoot%\system32", Some(ValueKind::ExpandSz), &vars),
            r"C:\WINDOWS\system32"
        );
    }

    #[test]
    fn absoluteness_follows_windows_rules() {
        for absolute in [
            r"C:\one",
            "C:/one",
            r"\\server\share",
            r"\\?\C:\one",
            r"z:\one",
        ] {
            assert!(is_absolute(absolute), "{absolute} should be absolute");
        }
        for relative in ["bin", ".", "..", r"\bin", "/bin", "C:bin", "", "C:"] {
            assert!(!is_absolute(relative), "{relative} should be relative");
        }
    }

    #[test]
    fn canonical_keys_ignore_case_and_trailing_separators() {
        assert_eq!(canonical_key(r"C:\One\"), canonical_key(r"c:\one"));
        assert_eq!(canonical_key(r"C:\One//"), canonical_key(r"C:\one"));
        // Drive root and drive-relative stay distinct.
        assert_ne!(canonical_key(r"C:\"), canonical_key("C:"));
    }

    #[test]
    fn machine_entries_come_before_user_entries() {
        let machine = scope(r"C:\m1;C:\m2", ValueKind::Sz);
        let user = scope(r"C:\u1", ValueKind::Sz);

        let entries = compose(Some(&machine), Some(&user), None, &no_vars);

        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].raw, r"C:\m1");
        assert_eq!(entries[1].raw, r"C:\m2");
        assert_eq!(entries[2].raw, r"C:\u1");
        assert_eq!(entries[0].scope, PathScope::Machine);
        assert_eq!(entries[1].scope, PathScope::Machine);
        assert_eq!(entries[2].scope, PathScope::User);
        for (position, entry) in entries.iter().enumerate() {
            assert_eq!(entry.index, position);
        }
    }

    #[test]
    fn a_missing_scope_is_skipped_rather_than_faked() {
        let user = scope(r"C:\u1", ValueKind::Sz);

        let entries = compose(None, Some(&user), None, &no_vars);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].index, 0);
        assert_eq!(entries[0].scope, PathScope::User);
    }

    #[test]
    fn the_stored_form_is_kept_alongside_the_resolved_one() {
        let machine = scope(
            r"%SystemRoot%\system32;C:\Program Files\Git\cmd",
            ValueKind::ExpandSz,
        );

        let entries = compose(Some(&machine), None, None, &vars);

        assert_eq!(entries[0].raw, r"%SystemRoot%\system32");
        assert_eq!(entries[0].expanded.as_deref(), Some(r"C:\WINDOWS\system32"));
        assert_eq!(entries[0].value_kind, Some(ValueKind::ExpandSz));
        assert_eq!(entries[0].effective(), r"C:\WINDOWS\system32");

        // Nothing to expand, so there is no second form to report.
        assert_eq!(entries[1].expanded, None);
        assert_eq!(entries[1].effective(), r"C:\Program Files\Git\cmd");
    }

    #[test]
    fn a_stray_separator_is_reported_as_empty() {
        let machine = scope(r"C:\one;;C:\two", ValueKind::Sz);

        let entries = compose(Some(&machine), None, None, &no_vars);

        assert_eq!(entries.len(), 3);
        assert_eq!(entries[1].findings, vec![Finding::Empty]);
        assert!(entries[0].findings.is_empty());
        assert!(entries[2].findings.is_empty());
    }

    #[test]
    fn a_relative_entry_is_reported() {
        let machine = scope(r"C:\one;bin", ValueKind::Sz);

        let entries = compose(Some(&machine), None, None, &no_vars);

        assert_eq!(entries[1].findings, vec![Finding::Relative]);
    }

    #[test]
    fn a_repeat_points_at_the_entry_that_wins() {
        let machine = scope(r"C:\One;C:\Program Files", ValueKind::Sz);
        let user = scope(r"C:\one\", ValueKind::Sz);

        let entries = compose(Some(&machine), Some(&user), None, &no_vars);

        assert!(entries[0].findings.is_empty());
        assert_eq!(
            entries[2].findings,
            vec![Finding::Duplicate { first_seen_at: 0 }]
        );
    }

    #[test]
    fn expansion_can_reveal_a_duplicate() {
        // Stored differently, same directory once resolved.
        let machine = scope(r"%SystemRoot%;C:\WINDOWS", ValueKind::ExpandSz);

        let entries = compose(Some(&machine), None, None, &vars);

        assert_eq!(
            entries[1].findings,
            vec![Finding::Duplicate { first_seen_at: 0 }]
        );
    }

    #[test]
    fn a_runtime_injected_directory_is_process_only() {
        let machine = scope(r"C:\m1", ValueKind::Sz);
        let user = scope(r"C:\u1", ValueKind::Sz);
        let process = r"C:\shim;C:\m1;C:\u1";

        let entries = compose(Some(&machine), Some(&user), Some(process), &no_vars);

        assert_eq!(entries.len(), 3);
        let injected = &entries[2];
        assert_eq!(injected.scope, PathScope::ProcessOnly);
        assert_eq!(injected.raw, r"C:\shim");
        // Nothing was read from the registry for it, so there is no value kind.
        assert_eq!(injected.value_kind, None);
        // Being injected at runtime is legitimate, not a finding.
        assert!(injected.findings.is_empty());
    }

    #[test]
    fn a_registry_entry_is_not_repeated_as_process_only() {
        let machine = scope(r"C:\One", ValueKind::Sz);
        // Same directory, different spelling, plus a stray separator.
        let process = r"c:\one\;;C:\One";

        let entries = compose(Some(&machine), None, Some(process), &no_vars);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].scope, PathScope::Machine);
    }

    #[test]
    fn process_only_entries_are_deduplicated_against_each_other() {
        let process = r"C:\shim;C:\shim\";

        let entries = compose(None, None, Some(process), &no_vars);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].scope, PathScope::ProcessOnly);
    }
}
