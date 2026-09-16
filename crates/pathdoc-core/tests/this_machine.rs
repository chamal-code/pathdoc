//! Machine-specific acceptance test for `PATH` composition and resolution.
//!
//! Everything asserted here describes the machine pathdoc was written on. It is
//! expected to fail anywhere else, which is why it is an integration test of its
//! own instead of leaking into the unit tests, which stay portable.
//!
//! # When this fails, the machine changed
//!
//! **Do not adjust a number to make it pass.** Find out what moved first. Two
//! agent sessions edit this machine: machine-wide changes are the trunk's
//! responsibility and the trunk announces them, so a red test here means ask the
//! trunk what it did. A baseline that gets edited whenever reality disagrees is
//! not a baseline.
//!
//! It has already earned its keep twice. On 2026-09-16 at 17:48 the trunk
//! appended `%APPDATA%\fnm\aliases\default` to the user `PATH` while configuring
//! an MCP server — `npx.cmd` could not find `node`, because `fnm` only exposes it
//! inside shells it has activated. The same session's edits also rewrote the value
//! as `REG_SZ`, because `[Environment]::SetEnvironmentVariable` writes `REG_SZ`
//! unconditionally rather than choosing by content, as is widely assumed. That was
//! restored to `REG_EXPAND_SZ` afterwards; the assertion below is what would catch
//! it happening again.
//!
//! Useful when investigating, and note `DoNotExpandEnvironmentNames` — read
//! without it and you see expanded paths, which is how an indirection gets written
//! back over as a literal:
//!
//! ```powershell
//! (Get-Item 'HKCU:\Environment').GetValueKind('Path')
//! (Get-Item 'HKCU:\Environment').GetValue('Path', $null, 'DoNotExpandEnvironmentNames')
//! ```

use std::process::Command;

use pathdoc_core::{
    AuditReport, Capability, Finding, PathEntry, PathScope, Resolved, ValueKind, audit,
};

// ---------------------------------------------------------------------------
// VOLATILE. Read from the live registry on 2026-09-16 at 18:20 and pinned here.
// These move whenever anything is installed. Re-read before changing them, and
// ask the trunk what it did — do not take a number on trust, including from the
// trunk: a list that was authoritative when it was written decayed within
// minutes on the day these were established.
// ---------------------------------------------------------------------------

/// Entries in `HKLM`. Went 8 to 10 when GitHub CLI and starship were installed.
const MACHINE_ENTRIES: usize = 10;

/// Entries in `HKCU`. Went 14 to 17: `fnm\aliases\default`, zoxide, just and dust
/// were appended, and the dead `Programs\Ollama` entry was pruned.
const USER_ENTRIES: usize = 17;

/// winget's installers append a trailing `;` when they add a package directory,
/// and the trunk's edits strip it again because they rebuild the value from a
/// filtered split. So this flips between 0 and 1 depending on which happened last.
///
/// It does **not** accumulate: five backups taken across 2026-09-16 showed exactly
/// one empty segment or none, never two. A single separator being re-added, not a
/// growing tail.
const TRAILING_EMPTY_SEGMENTS: usize = 0;

/// Index of `C:\Program Files\Git\cmd`. Stable so far: the entries added since
/// went after it.
const GIT_FOR_WINDOWS: usize = 7;

// ---------------------------------------------------------------------------
// Durable. Directory suffixes rather than indices, so installing something does
// not invalidate them.
// ---------------------------------------------------------------------------

/// Where uv and its shims are installed, and what must win over hermes' copy.
const WINGET_LINKS: &str = r"\AppData\Local\Microsoft\WinGet\Links";
/// Where uv puts its Python shims.
const LOCAL_BIN: &str = r"\.local\bin";
/// hermes' vendored tools.
const HERMES_BIN: &str = r"\AppData\Local\hermes\bin";
/// hermes' first vendored git.
const HERMES_GIT_CMD: &str = r"\AppData\Local\hermes\git\cmd";
/// hermes' second vendored git.
const HERMES_GIT_BIN: &str = r"\AppData\Local\hermes\git\bin";
/// hermes' vendored coreutils — the source of `gzip`, `unzip`, `sdiff`.
const HERMES_GIT_USR_BIN: &str = r"\AppData\Local\hermes\git\usr\bin";
/// Git for Windows, the real install.
const GIT_FOR_WINDOWS_DIR: &str = r"C:\Program Files\Git\cmd";

fn report() -> AuditReport {
    match audit() {
        Ok(report) => report,
        Err(err) => panic!("audit failed: {err}"),
    }
}

fn in_scope(report: &AuditReport, scope: PathScope) -> Vec<&PathEntry> {
    report
        .entries
        .iter()
        .filter(|entry| entry.scope == scope)
        .collect()
}

/// Only the entries that came from the registry, which is what the counts above
/// describe. Process-only entries depend on which shell is running the test.
fn from_registry(report: &AuditReport) -> Vec<&PathEntry> {
    report
        .entries
        .iter()
        .filter(|entry| entry.scope != PathScope::ProcessOnly)
        .collect()
}

fn resolved<'a>(report: &'a AuditReport, stem: &str) -> &'a Resolved {
    match report
        .executables
        .iter()
        .find(|candidate| candidate.stem == stem)
    {
        Some(found) => found,
        None => panic!("`{stem}` resolves from nowhere on this PATH"),
    }
}

/// Assert which copy a **newly started process** would run.
///
/// Every "who wins" claim below uses this rather than live order, deliberately.
/// `fresh_winner` ignores process-only directories, which makes it independent of
/// whatever the harness injected into this process — and harnesses inject plenty.
/// `just` running recipes through a vendored MSYS `sh` put a second `git.exe` and
/// `bash.exe` at the front of the live PATH and broke two assertions that had been
/// keyed on live position.
fn assert_fresh_winner(resolved: &Resolved, directory_suffix: &str, file_name: &str) {
    let Some(winner) = resolved.fresh_winner() else {
        panic!(
            "`{}` would resolve from nowhere in a new process; occurrences: {:?}",
            resolved.stem,
            directories(resolved)
        )
    };

    assert!(
        winner.directory.ends_with(directory_suffix),
        "`{}` would resolve from {:?}, expected something ending {directory_suffix:?}",
        resolved.stem,
        winner.directory
    );
    assert_eq!(winner.file_name, file_name);
    // A fresh process has no runtime injection at all.
    assert_ne!(winner.scope, PathScope::ProcessOnly);
}

/// Assert a copy exists in a given directory, without claiming anything about rank.
fn assert_present_in(resolved: &Resolved, directory_suffix: &str, file_name: &str) {
    assert!(
        resolved.occurrences.iter().any(|occurrence| {
            occurrence.directory.ends_with(directory_suffix) && occurrence.file_name == file_name
        }),
        "`{}` has no copy in a directory ending {directory_suffix:?}; occurrences: {:?}",
        resolved.stem,
        directories(resolved)
    );
}

/// Assert one directory outranks another in composed order, which is the ordering
/// the registry decides and no harness can disturb.
fn assert_outranks(resolved: &Resolved, winner_suffix: &str, loser_suffix: &str) {
    let index_of = |suffix: &str| {
        resolved
            .occurrences
            .iter()
            .find(|occurrence| occurrence.directory.ends_with(suffix))
            .map(|occurrence| occurrence.entry_index)
    };

    match (index_of(winner_suffix), index_of(loser_suffix)) {
        (Some(winner), Some(loser)) => assert!(
            winner < loser,
            "`{}`: {winner_suffix:?} is at index {winner}, expected it to precede \
             {loser_suffix:?} at {loser}",
            resolved.stem
        ),
        _ => panic!(
            "`{}` is missing one of {winner_suffix:?} or {loser_suffix:?}; occurrences: {:?}",
            resolved.stem,
            directories(resolved)
        ),
    }
}

fn directories(resolved: &Resolved) -> Vec<&str> {
    resolved
        .occurrences
        .iter()
        .map(|occurrence| occurrence.directory.as_str())
        .collect()
}

/// `[Environment]::GetEnvironmentVariable('Path', scope)` — the independent
/// reference. It reads the same two registry values and expands them, so it is a
/// genuinely separate code path to the same answer.
fn powershell_scope(scope: &str) -> Vec<String> {
    let script = format!("[Environment]::GetEnvironmentVariable('Path','{scope}')");
    let output = match Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
    {
        Ok(output) => output,
        Err(err) => panic!("cannot run powershell: {err}"),
    };
    assert!(
        output.status.success(),
        "powershell failed for scope {scope}"
    );

    String::from_utf8_lossy(&output.stdout)
        .trim()
        .split(';')
        .filter(|segment| !segment.trim().is_empty())
        .map(str::to_owned)
        .collect()
}

// ---------------------------------------------------------------------------
// Composition
// ---------------------------------------------------------------------------

#[test]
fn scope_counts_match_the_verified_baseline() {
    let report = report();
    let machine = in_scope(&report, PathScope::Machine);
    let user = in_scope(&report, PathScope::User);

    assert_eq!(machine.len(), MACHINE_ENTRIES, "machine entries");
    assert_eq!(user.len(), USER_ENTRIES, "user entries");

    // Registry entries take the first indices, contiguously, machine first.
    for (position, entry) in machine.iter().chain(user.iter()).enumerate() {
        assert_eq!(entry.index, position);
    }
}

#[test]
fn both_scopes_are_stored_expandable() {
    let report = report();

    // The assertion that would have caught the REG_SZ downgrade. HKLM needs it
    // because it genuinely contains `%SystemRoot%`; HKCU contains no references at
    // all today, and is still ExpandString because that is what Windows wrote and
    // nothing should silently change it.
    for entry in from_registry(&report) {
        assert_eq!(
            entry.value_kind,
            Some(ValueKind::ExpandSz),
            "entry {} ({:?}) is not REG_EXPAND_SZ",
            entry.index,
            entry.effective()
        );
    }
}

#[test]
fn pinned_indices_are_where_windows_puts_them() {
    let report = report();

    let first = &report.entries[0];
    assert_eq!(first.effective(), r"C:\WINDOWS\system32");
    // Ground truth for the raw-versus-expanded distinction: stored as an
    // environment reference, reported as both facts, neither one blurred into the
    // other.
    assert_eq!(first.raw, r"%SystemRoot%\system32");
    assert_eq!(first.expanded.as_deref(), Some(r"C:\WINDOWS\system32"));
    assert_eq!(first.value_kind, Some(ValueKind::ExpandSz));
    assert_eq!(first.scope, PathScope::Machine);

    // This is the one that beats both vendored gits, purely because machine PATH
    // is composed before user PATH.
    let git = &report.entries[GIT_FOR_WINDOWS];
    assert_eq!(git.effective(), GIT_FOR_WINDOWS_DIR);
    assert_eq!(git.scope, PathScope::Machine);
    // Stored expandable but with nothing to expand, so there is no second form.
    assert_eq!(git.expanded, None);

    // First user entry, immediately after the machine block.
    let first_user = &report.entries[MACHINE_ENTRIES];
    assert!(
        first_user.effective().ends_with(r"\.cargo\bin"),
        "first user entry was {:?}",
        first_user.effective()
    );
    assert_eq!(first_user.scope, PathScope::User);
}

#[test]
fn the_machine_scope_stores_its_windows_paths_as_references() {
    let report = report();

    // The first five machine entries are all `%SystemRoot%` forms, in two
    // different casings. Every one must report a raw and an expanded value that
    // differ, or the expansion is being lost somewhere.
    for index in 0..5 {
        let entry = &report.entries[index];
        assert!(
            entry.raw.to_lowercase().starts_with("%systemroot%"),
            "entry {index} raw was {:?}",
            entry.raw
        );
        assert!(
            entry.expanded.is_some(),
            "entry {index} stores a reference but reports no expansion"
        );
        assert!(
            entry.effective().to_lowercase().starts_with(r"c:\windows"),
            "entry {index} expanded to {:?}",
            entry.effective()
        );
    }
}

#[test]
fn the_registry_path_is_clean() {
    let report = report();

    // `Programs\Ollama` was pruned, so nothing on PATH in the registry is dead.
    // Deliberately scoped to registry entries: a process older than the prune still
    // carries it, which is a fact about that process rather than the machine.
    let dead: Vec<&str> = from_registry(&report)
        .iter()
        .filter(|entry| entry.findings.contains(&Finding::Missing))
        .map(|entry| entry.effective())
        .collect();
    assert!(dead.is_empty(), "dead registry entries: {dead:?}");

    let empty = from_registry(&report)
        .iter()
        .filter(|entry| entry.findings.contains(&Finding::Empty))
        .count();
    assert_eq!(
        empty, TRAILING_EMPTY_SEGMENTS,
        "stray separators in the registry value"
    );

    // Nothing else at all. A duplicate or an unreadable directory should fail here
    // rather than hide behind the counts above.
    for entry in from_registry(&report) {
        for finding in &entry.findings {
            assert_eq!(
                *finding,
                Finding::Empty,
                "unexpected {finding:?} on entry {} ({:?})",
                entry.index,
                entry.effective()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Process-only entries: mechanisms and relationships, never counts.
//
// How many entries the running process can or cannot see is a property of that
// process's history, not of the machine. Three observers disagreed on the same
// afternoon and every one of them was right. A shell started before the trunk's
// installs saw seven registry entries as unreachable. A long-lived shell that had
// been given `$env:Path = machine + ';' + user` saw none, having dropped the
// injected shim while keeping `FNM_MULTISHELL_PATH` set — a state impossible in a
// clean shell. And a `cargo test` binary sees four extra injected directories that
// cargo prepends.
//
// So nothing below counts anything. The arithmetic of live-versus-composed ordering
// is unit-tested against synthetic PATHs in `executables.rs` and `compose.rs`, where
// both sides are controlled. These only confirm the mechanism is real here.
// ---------------------------------------------------------------------------

#[test]
fn a_process_only_entry_is_by_definition_one_this_process_can_see() {
    let report = report();

    for entry in in_scope(&report, PathScope::ProcessOnly) {
        // The relationship that defines the scope: in the process block, in neither
        // registry scope.
        assert!(
            entry.is_live(),
            "{:?} is process-only yet has no live position",
            entry.effective()
        );
        // Nothing in the registry produced it, so there is no value kind to report.
        assert_eq!(entry.value_kind, None);
        // Runtime injection lands after the registry block, never inside it.
        assert!(entry.index >= MACHINE_ENTRIES + USER_ENTRIES);
    }
}

#[test]
fn a_registry_entry_without_a_live_position_is_not_an_error() {
    let report = report();

    // Whether any exist depends on when this process started, so that is not
    // asserted. What is asserted is that being unseen is never itself a finding.
    for entry in from_registry(&report) {
        if !entry.is_live() {
            assert!(
                entry.findings.is_empty(),
                "{:?} is merely unseen by this process, but was flagged {:?}",
                entry.effective(),
                entry.findings
            );
        }
    }
}

#[test]
fn the_fnm_shim_is_process_only_and_carries_no_findings() {
    let process = std::env::var("PATH").unwrap_or_default();
    if !process.to_lowercase().contains("fnm_multishells") {
        // fnm activates per shell. Nothing to assert if it did not.
        return;
    }

    let report = report();
    let injected = in_scope(&report, PathScope::ProcessOnly);

    // Deliberately not asserting a count. `cargo test` prepends its own
    // directories to the child process PATH, so a test binary sees more runtime
    // injection than the shell that launched it.
    let Some(shim) = injected
        .iter()
        .find(|entry| entry.effective().contains("fnm_multishells"))
    else {
        panic!(
            "the fnm shim is on the process PATH but was not reported as process-only; got {:?}",
            injected
                .iter()
                .map(|entry| entry.effective())
                .collect::<Vec<_>>()
        )
    };

    // Injected at runtime is legitimate, not a problem to report.
    assert!(
        shim.findings.is_empty(),
        "the fnm shim must not be flagged: {:?}",
        shim.findings
    );
    // And it is injected ahead of the registry block, which is the whole reason
    // live position has to be tracked separately from composed index.
    //
    // Not asserted as position 0: `cargo test` prepends its own directories to the
    // child PATH, so inside a test binary the shim sits behind those. The durable
    // claim is that it comes before `system32`, whatever else got in front.
    let system32 = report.entries[0].process_position;
    assert!(
        shim.process_position < system32,
        "shim at {:?} should precede system32 at {system32:?}",
        shim.process_position
    );
}

#[test]
fn composed_order_matches_powershell() {
    let report = report();

    for (scope, label) in [(PathScope::Machine, "Machine"), (PathScope::User, "User")] {
        let ours = in_scope(&report, scope);
        let reference = powershell_scope(label);

        // PowerShell drops the empty trailing segment, so compare the entries that
        // actually name a directory.
        let named: Vec<&&PathEntry> = ours
            .iter()
            .filter(|entry| !entry.effective().is_empty())
            .collect();

        assert_eq!(
            named.len(),
            reference.len(),
            "{label}: entry count disagrees with PowerShell"
        );
        for (position, (entry, expected)) in named.iter().zip(&reference).enumerate() {
            assert!(
                entry.effective().eq_ignore_ascii_case(expected),
                "{label} index {position}: composed {:?}, PowerShell says {expected:?}",
                entry.effective()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Executable resolution. These are the bullets in docs/SPEC.md that only
// enumeration could close, and the reason the tool exists: every one of them was
// found by hand during provisioning.
// ---------------------------------------------------------------------------

#[test]
fn pathext_is_longer_than_the_documented_default_on_this_machine() {
    // The reason PATHEXT is read from the environment rather than hard-coded:
    // this machine carries `.CPL` as well, and `powercfg.cpl` sits beside
    // `powercfg.exe` in system32.
    let pathext = std::env::var("PATHEXT").unwrap_or_default().to_lowercase();

    assert!(pathext.contains(".cpl"), "PATHEXT was {pathext:?}");
}

#[test]
fn git_for_windows_beats_both_vendored_copies() {
    let report = report();
    let git = resolved(&report, "git");

    assert!(git.is_shadowed());
    assert!(!git.is_pathext_only());

    // Both vendored copies are present, and the real install outranks each of them.
    // Not asserted as exactly three: a harness that injects an MSYS `sh` adds a
    // fourth from hermes' `mingw64\bin`, and the count is then a fact about the
    // harness. The ranking is the durable claim, and it is the one the spec makes.
    assert_present_in(git, HERMES_GIT_CMD, "git.exe");
    assert_present_in(git, HERMES_GIT_BIN, "git.exe");
    assert_outranks(git, GIT_FOR_WINDOWS_DIR, HERMES_GIT_CMD);
    assert_outranks(git, GIT_FOR_WINDOWS_DIR, HERMES_GIT_BIN);

    // Machine PATH is composed before user PATH, which is the entire reason the real
    // install wins here without anybody having intervened.
    assert_fresh_winner(git, GIT_FOR_WINDOWS_DIR, "git.exe");
}

#[test]
fn the_vendored_unix_tools_are_named_even_though_nothing_competes_with_them() {
    let report = report();

    // All three appear exactly once, so a conflicts-only report could never have
    // mentioned them — and "gzip comes out of a chat client's private folder" is
    // precisely the fact worth surfacing.
    for stem in ["gzip", "unzip", "sdiff"] {
        let tool = resolved(&report, stem);

        // The point is provenance, not rank: nothing competes with these, and a
        // conflicts-only report could never have named them.
        assert_fresh_winner(tool, HERMES_GIT_USR_BIN, &format!("{stem}.exe"));
    }
}

#[test]
fn bash_resolves_inside_hermes() {
    let report = report();
    let bash = resolved(&report, "bash");

    // Two copies in the registry, both vendored. A harness running an MSYS `sh`
    // adds more, so again the ranking is asserted and not the count.
    assert_present_in(bash, HERMES_GIT_BIN, "bash.exe");
    assert_present_in(bash, HERMES_GIT_USR_BIN, "bash.exe");
    assert_outranks(bash, HERMES_GIT_BIN, HERMES_GIT_USR_BIN);
    assert_fresh_winner(bash, HERMES_GIT_BIN, "bash.exe");
}

#[test]
fn python_resolves_from_local_bin_with_no_store_stub_left() {
    let report = report();
    let python = resolved(&report, "python");

    assert_fresh_winner(python, LOCAL_BIN, "python.exe");
    assert!(
        !python.is_shadowed(),
        "expected one python.exe, found {:?}",
        directories(python)
    );

    // The App Execution Aliases were turned off during provisioning. If one comes
    // back it will land in WindowsApps and win nothing, but it would show up here.
    assert!(
        !python
            .occurrences
            .iter()
            .any(|occurrence| occurrence.directory.contains("WindowsApps")),
        "a WindowsApps stub is back on PATH"
    );
    assert!(
        !python
            .occurrences
            .iter()
            .any(|occurrence| occurrence.is_reparse_point),
        "python.exe should be a real binary, not an alias stub"
    );
}

#[test]
fn versioned_python_shims_are_separate_programs() {
    let report = report();

    // `python3.11.exe` must not be filed under `python3`. Only the matched
    // PATHEXT extension comes off the end of a name.
    let python3 = resolved(&report, "python3");
    assert_fresh_winner(python3, LOCAL_BIN, "python3.exe");
    assert!(!python3.is_shadowed());

    let pinned = resolved(&report, "python3.11");
    assert_fresh_winner(pinned, LOCAL_BIN, "python3.11.exe");
}

#[test]
fn our_uv_beats_the_vendored_one_on_user_path_order() {
    let report = report();

    // WinGet\Links was moved to the front of the user PATH during provisioning
    // precisely so this would be the outcome. Same for uv's sibling shims.
    for stem in ["uv", "uvx", "uvw"] {
        let tool = resolved(&report, stem);

        assert!(tool.is_shadowed(), "`{stem}` should appear more than once");
        assert_present_in(tool, WINGET_LINKS, &format!("{stem}.exe"));
        assert_present_in(tool, HERMES_BIN, &format!("{stem}.exe"));
        assert_outranks(tool, WINGET_LINKS, HERMES_BIN);
        assert_fresh_winner(tool, WINGET_LINKS, &format!("{stem}.exe"));

        // WinGet\Links holds symlinks to the real package, and the winner being a
        // reparse point is reported rather than resolved away. The other side of
        // this is `python.exe`, which is a real binary and must not be flagged.
        let Some(winner) = tool.fresh_winner() else {
            panic!("`{stem}` would resolve from nowhere")
        };
        assert!(
            winner.is_reparse_point,
            "`{stem}` in WinGet\\Links is a symlink and should be reported as one"
        );
    }
}

#[test]
fn a_contest_inside_system32_is_decided_by_pathext_not_path() {
    let report = report();
    let powercfg = resolved(&report, "powercfg");

    // Both live in system32. `.exe` outranks `.cpl` in PATHEXT, and no amount of
    // reordering PATH would change that.
    assert!(powercfg.is_shadowed());
    assert!(powercfg.is_pathext_only());
    assert_present_in(powercfg, r"\WINDOWS\system32", "powercfg.exe");
    assert_present_in(powercfg, r"\WINDOWS\system32", "powercfg.cpl");
    // Same directory, so PATHEXT rank breaks the tie and `.exe` outranks `.cpl`.
    assert_fresh_winner(powercfg, r"\WINDOWS\system32", "powercfg.exe");
}

#[test]
fn node_is_the_live_example_of_a_context_dependent_winner() {
    let process = std::env::var("PATH").unwrap_or_default();
    if !process.to_lowercase().contains("fnm_multishells") {
        // No shim in this shell, so there is no contest to have.
        return;
    }

    let report = report();
    let node = resolved(&report, "node");

    // At least two copies since 2026-09-16: `fnm\aliases\default`, a registry entry,
    // and the per-shell `fnm_multishells` shim, which is process-only. Not asserted
    // as exactly two — how many copies a process can see is that process's history,
    // and the relationship below is what actually matters.
    assert!(
        node.is_shadowed(),
        "expected node.exe more than once, found {:?}",
        directories(node)
    );

    // Runtime injection goes to the front of the live PATH, so the shim runs now.
    let Some(live) = node.live_winner() else {
        panic!("nothing on this process's PATH answers to node")
    };
    assert!(
        live.directory.contains("fnm_multishells"),
        "live winner was {:?}",
        live.directory
    );
    assert_eq!(live.scope, PathScope::ProcessOnly);

    // A fresh process has no shim, so it falls through to the registry entry.
    let Some(fresh) = node.fresh_winner() else {
        panic!("a new process would resolve node from nowhere")
    };
    assert!(
        fresh.directory.ends_with(r"\fnm\aliases\default"),
        "fresh winner was {:?}",
        fresh.directory
    );
    assert_ne!(fresh.scope, PathScope::ProcessOnly);

    // This is the case that was reported wrongly before schema 3.
    assert!(node.winner_depends_on_context());
}

#[test]
fn enumeration_ran_and_nothing_on_this_path_refused_to_open() {
    let report = report();

    assert!(report.computed(Capability::ShadowDetection));
    assert!(
        report.executables.len() > 500,
        "system32 alone should account for hundreds of names, got {}",
        report.executables.len()
    );

    // Nothing on this PATH is ACL-locked. If that ever changes this is the test
    // that will say so, rather than a count quietly shifting.
    let unreadable: Vec<&str> = report
        .entries
        .iter()
        .filter(|entry| entry.findings.contains(&Finding::Unreadable))
        .map(PathEntry::effective)
        .collect();
    assert!(unreadable.is_empty(), "unreadable: {unreadable:?}");
}
