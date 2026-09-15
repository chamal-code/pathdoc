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
//!
//! The independent reference for order is PowerShell's own view of the two
//! scopes, which is queried rather than hard-coded.

use std::process::Command;

use pathdoc_core::{AuditReport, Finding, PathEntry, PathScope, ValueKind, audit};

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
