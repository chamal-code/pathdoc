//! Machine-specific acceptance test for `PATH` composition.
//!
//! Everything asserted here encodes the `PATH` layout of the machine pathdoc was
//! written on, established by hand during provisioning on 2026-09-15 and
//! recorded in `docs/SPEC.md` under Verification. It is expected to fail
//! anywhere else, which is exactly why it lives in its own integration test
//! instead of leaking into the unit tests, which stay portable.
//!
//! Expected state, for reference:
//!
//! | Fact | Value |
//! | --- | --- |
//! | machine entries | 8 |
//! | user entries | 14 |
//! | composed registry entries | 22 |
//! | index 0 | `C:\WINDOWS\system32`, stored as `%SystemRoot%\system32` |
//! | index 7 | `C:\Program Files\Git\cmd` |
//! | index 8 | `C:\Users\Chamal Upulitha\.cargo\bin`, first user entry |
//! | dead entries | exactly one, `...\AppData\Local\Programs\Ollama` |
//! | injected | `fnm_multishells`, process-only and clean |
//! | `git.exe` | three, `C:\Program Files\Git\cmd` winning |
//! | `bash.exe` | two, both vendored inside `hermes` |
//! | `gzip`, `unzip`, `sdiff` | one each, all vendored inside `hermes` |
//! | `python.exe` | one, `~\.local\bin`, no `WindowsApps` stub |
//! | `uv.exe` | two, `...\WinGet\Links` winning |
//!
//! The independent reference for order is PowerShell's own view of the two
//! scopes, which is queried rather than hard-coded.

use std::process::Command;

use pathdoc_core::{AuditReport, Finding, PathEntry, PathScope, Resolved, ValueKind, audit};

/// Number of entries the machine scope contributes on this machine.
const MACHINE_ENTRIES: usize = 8;
/// Number of entries the user scope contributes on this machine.
const USER_ENTRIES: usize = 14;

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

fn assert_same_order(ours: &[&PathEntry], reference: &[String], scope: &str) {
    assert_eq!(
        ours.len(),
        reference.len(),
        "{scope}: entry count disagrees with PowerShell"
    );
    for (position, (entry, expected)) in ours.iter().zip(reference).enumerate() {
        assert!(
            entry.effective().eq_ignore_ascii_case(expected),
            "{scope} index {position}: composed {:?}, PowerShell says {expected:?}",
            entry.effective()
        );
    }
}

#[test]
fn scope_counts_match_provisioning() {
    let report = report();
    let machine = in_scope(&report, PathScope::Machine);
    let user = in_scope(&report, PathScope::User);

    assert_eq!(machine.len(), MACHINE_ENTRIES, "machine entries");
    assert_eq!(user.len(), USER_ENTRIES, "user entries");
    assert_eq!(
        machine.len() + user.len(),
        MACHINE_ENTRIES + USER_ENTRIES,
        "composed registry entries"
    );

    // Registry entries take the first indices, contiguously, machine first.
    for (position, entry) in machine.iter().chain(user.iter()).enumerate() {
        assert_eq!(entry.index, position);
    }
}

#[test]
fn pinned_indices_are_where_windows_puts_them() {
    let report = report();

    let first = &report.entries[0];
    assert_eq!(first.effective(), r"C:\WINDOWS\system32");
    // Stored literally as an environment reference, and reported as both facts.
    assert_eq!(first.raw, r"%SystemRoot%\system32");
    assert_eq!(first.expanded.as_deref(), Some(r"C:\WINDOWS\system32"));
    assert_eq!(first.value_kind, Some(ValueKind::ExpandSz));
    assert_eq!(first.scope, PathScope::Machine);

    // Last machine entry. This is the one that beats both vendored gits, purely
    // because machine PATH is composed before user PATH.
    let last_machine = &report.entries[MACHINE_ENTRIES - 1];
    assert_eq!(last_machine.effective(), r"C:\Program Files\Git\cmd");
    assert_eq!(last_machine.scope, PathScope::Machine);
    // Stored expandable but with nothing to expand, so there is no second form.
    assert_eq!(last_machine.value_kind, Some(ValueKind::ExpandSz));
    assert_eq!(last_machine.expanded, None);

    // First user entry, immediately after the machine block.
    let first_user = &report.entries[MACHINE_ENTRIES];
    assert_eq!(
        first_user.effective(),
        r"C:\Users\Chamal Upulitha\.cargo\bin"
    );
    assert_eq!(first_user.scope, PathScope::User);
    assert_eq!(first_user.value_kind, Some(ValueKind::ExpandSz));
    assert_eq!(first_user.expanded, None);
}

#[test]
fn the_only_dead_entry_is_ollama() {
    let report = report();

    let dead: Vec<&PathEntry> = report
        .entries
        .iter()
        .filter(|entry| entry.findings.contains(&Finding::Missing))
        .collect();

    assert_eq!(
        dead.len(),
        1,
        "expected exactly one dead entry, got {:?}",
        dead.iter().map(|e| e.effective()).collect::<Vec<_>>()
    );
    assert!(
        dead[0]
            .effective()
            .ends_with(r"\AppData\Local\Programs\Ollama"),
        "unexpected dead entry: {:?}",
        dead[0].effective()
    );
    assert_eq!(dead[0].scope, PathScope::User);
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
    // directories — `target\debug`, `target\debug\deps` and the toolchain's
    // `bin` and `lib\rustlib` — to the child process PATH, so a test binary sees
    // more runtime injection than the shell that launched it. The claim being
    // verified is about the fnm shim specifically.
    let shim = injected
        .iter()
        .find(|entry| entry.effective().contains("fnm_multishells"));
    let Some(shim) = shim else {
        panic!(
            "the fnm shim is on the process PATH but was not reported as process-only; got {:?}",
            injected
                .iter()
                .map(|entry| entry.effective())
                .collect::<Vec<_>>()
        );
    };

    // Injected at runtime is legitimate, not a problem to report.
    assert!(
        shim.findings.is_empty(),
        "the fnm shim must not be flagged: {:?}",
        shim.findings
    );
    // It did not come from the registry, so there is no value kind to record.
    assert_eq!(shim.value_kind, None);
    assert_eq!(shim.expanded, None);

    // Runtime injection lands after the registry block, never inside it.
    for entry in &injected {
        assert!(
            entry.index >= MACHINE_ENTRIES + USER_ENTRIES,
            "process-only entry {:?} landed inside the registry block at index {}",
            entry.effective(),
            entry.index
        );
    }
}

#[test]
fn composed_order_matches_powershell() {
    let report = report();

    assert_same_order(
        &in_scope(&report, PathScope::Machine),
        &powershell_scope("Machine"),
        "machine",
    );
    assert_same_order(
        &in_scope(&report, PathScope::User),
        &powershell_scope("User"),
        "user",
    );
}

// ---------------------------------------------------------------------------
// Executable resolution. These are the four bullets in docs/SPEC.md that only
// enumeration could close, and they are the whole reason the tool exists: every
// one of them was found by hand during provisioning.
// ---------------------------------------------------------------------------

/// Index of `C:\Program Files\Git\cmd`, the last machine entry.
const GIT_FOR_WINDOWS: usize = 7;
/// Index of `...\AppData\Local\Microsoft\WinGet\Links`.
const WINGET_LINKS: usize = 9;
/// Index of `...\.local\bin`, where uv puts its Python shims.
const LOCAL_BIN: usize = 10;
/// Index of `...\AppData\Local\hermes\bin`.
const HERMES_BIN: usize = 11;
/// Index of `...\AppData\Local\hermes\git\cmd`.
const HERMES_GIT_CMD: usize = 15;
/// Index of `...\AppData\Local\hermes\git\bin`.
const HERMES_GIT_BIN: usize = 16;
/// Index of `...\AppData\Local\hermes\git\usr\bin`, the vendored coreutils.
const HERMES_GIT_USR_BIN: usize = 17;

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

/// Assert one occurrence, by position, names the expected entry and file.
fn assert_occurrence(resolved: &Resolved, position: usize, entry_index: usize, file_name: &str) {
    let Some(occurrence) = resolved.occurrences.get(position) else {
        panic!(
            "`{}` has no occurrence {position}; it has {}",
            resolved.stem,
            resolved.occurrences.len()
        )
    };

    assert_eq!(
        occurrence.entry_index, entry_index,
        "`{}` occurrence {position} came from {} ({:?}), expected entry {entry_index}",
        resolved.stem, occurrence.entry_index, occurrence.directory
    );
    assert_eq!(occurrence.file_name, file_name);
}

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
    assert_eq!(
        git.occurrences.len(),
        3,
        "expected three git.exe, found {:?}",
        git.occurrences
            .iter()
            .map(|occurrence| occurrence.directory.as_str())
            .collect::<Vec<_>>()
    );

    // Machine PATH is composed before user PATH, which is the entire reason the
    // real install won here without anybody intervening.
    assert_occurrence(git, 0, GIT_FOR_WINDOWS, "git.exe");
    assert_occurrence(git, 1, HERMES_GIT_CMD, "git.exe");
    assert_occurrence(git, 2, HERMES_GIT_BIN, "git.exe");
    assert!(!git.is_pathext_only());

    let Some(winner) = git.winner() else {
        panic!("a shadowed name with no winner")
    };
    assert_eq!(winner.directory, r"C:\Program Files\Git\cmd");
}

#[test]
fn the_vendored_unix_tools_are_named_even_though_nothing_competes_with_them() {
    let report = report();

    // The correction that produced schema 2. All three appear exactly once, so a
    // conflicts-only report could never have mentioned them — and "gzip comes out
    // of a chat client's private folder" is precisely the fact worth surfacing.
    for stem in ["gzip", "unzip", "sdiff"] {
        let tool = resolved(&report, stem);

        assert!(
            !tool.is_shadowed(),
            "`{stem}` was expected to appear exactly once, found {:?}",
            tool.occurrences
                .iter()
                .map(|occurrence| occurrence.directory.as_str())
                .collect::<Vec<_>>()
        );
        assert_occurrence(tool, 0, HERMES_GIT_USR_BIN, &format!("{stem}.exe"));
    }
}

#[test]
fn bash_resolves_inside_hermes_twice_over() {
    let report = report();
    let bash = resolved(&report, "bash");

    assert!(bash.is_shadowed());
    assert_eq!(bash.occurrences.len(), 2);
    assert_occurrence(bash, 0, HERMES_GIT_BIN, "bash.exe");
    assert_occurrence(bash, 1, HERMES_GIT_USR_BIN, "bash.exe");
}

#[test]
fn python_resolves_from_local_bin_with_no_store_stub_left() {
    let report = report();
    let python = resolved(&report, "python");

    assert_occurrence(python, 0, LOCAL_BIN, "python.exe");
    assert!(
        !python.is_shadowed(),
        "expected one python.exe, found {:?}",
        python
            .occurrences
            .iter()
            .map(|occurrence| occurrence.directory.as_str())
            .collect::<Vec<_>>()
    );

    // The App Execution Aliases were turned off during provisioning. If one ever
    // comes back it will land in WindowsApps at index 12 and win nothing, but it
    // would still show up here.
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
    assert_occurrence(python3, 0, LOCAL_BIN, "python3.exe");
    assert!(!python3.is_shadowed());

    let pinned = resolved(&report, "python3.11");
    assert_occurrence(pinned, 0, LOCAL_BIN, "python3.11.exe");
}

#[test]
fn our_uv_beats_the_vendored_one_on_user_path_order() {
    let report = report();

    // WinGet\Links was moved to the front of the user PATH during provisioning
    // precisely so this would be the outcome. Same for uv's sibling shims.
    for stem in ["uv", "uvx", "uvw"] {
        let tool = resolved(&report, stem);

        assert!(tool.is_shadowed(), "`{stem}` should appear twice");
        assert_eq!(tool.occurrences.len(), 2);
        assert_occurrence(tool, 0, WINGET_LINKS, &format!("{stem}.exe"));
        assert_occurrence(tool, 1, HERMES_BIN, &format!("{stem}.exe"));

        // WinGet\Links holds symlinks to the real package, and the winner being a
        // reparse point is reported rather than resolved away. The other side of
        // this is `python.exe`, which is a real binary and must not be flagged.
        assert!(
            tool.occurrences[0].is_reparse_point,
            "`{stem}` in WinGet\\Links is a symlink and should be reported as one"
        );
        assert!(!tool.occurrences[1].is_reparse_point);
    }
}

#[test]
fn a_contest_inside_system32_is_decided_by_pathext_not_path() {
    let report = report();
    let powercfg = resolved(&report, "powercfg");

    // Both live in system32, entry 0. `.exe` outranks `.cpl` in PATHEXT, and no
    // amount of reordering PATH would change that.
    assert!(powercfg.is_shadowed());
    assert!(powercfg.is_pathext_only());
    assert_occurrence(powercfg, 0, 0, "powercfg.exe");
    assert_occurrence(powercfg, 1, 0, "powercfg.cpl");
}

#[test]
fn enumeration_ran_and_nothing_on_this_path_refused_to_open() {
    let report = report();

    assert!(report.computed(pathdoc_core::Capability::ShadowDetection));
    assert!(
        report.executables.len() > 500,
        "system32 alone should account for hundreds of names, got {}",
        report.executables.len()
    );

    // Nothing on this PATH is ACL-locked. If that ever changes this is the test
    // that will say so, rather than the count quietly shifting.
    let unreadable: Vec<&str> = report
        .entries
        .iter()
        .filter(|entry| entry.findings.contains(&Finding::Unreadable))
        .map(PathEntry::effective)
        .collect();
    assert!(unreadable.is_empty(), "unreadable: {unreadable:?}");
}
