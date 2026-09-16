//! Asking a shell what it answers to before `PATH` is ever searched.
//!
//! PowerShell resolves a bare name as alias, then function, then cmdlet, then
//! external file. So an alias or function shadows every executable of that name at a
//! layer `PATH` analysis cannot see. On the machine this was written for that is 24
//! names, including `sc` masking `sc.exe` — the Service Control tool — and `where`
//! masking `where.exe`.
//!
//! # Only a live shell can answer this
//!
//! The alternative is a table of known built-ins, which is fast, cannot see a user's
//! own aliases at all, and goes stale. So an interpreter is asked, and two things
//! about *which* interpreter are reported with every answer.
//!
//! The interpreter is identified by **absolute path**, because the verdict differs
//! between interpreters on one machine: `curl` is an alias for `Invoke-WebRequest`
//! under Windows PowerShell 5.1 and the real `curl.exe` under PowerShell 7. And the
//! path comes from this crate's own enumeration rather than a fresh name lookup —
//! resolving `powershell` by name would be a second, unaudited `PATH` search inside a
//! tool whose whole job is to distrust `PATH` searches.
//!
//! # The profile is not loaded unless asked for
//!
//! Loading a user profile means this tool executes arbitrary user code as a side
//! effect of producing a read-only report. That is a different tool. Built-ins appear
//! without a profile; a user's own alias needs one; both answers are legitimate, and
//! only one has side effects, so the one with side effects is opt-in.

use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::{Intercept, Resolved, ShellConstruct, ShellScan};

/// Interpreter to ask for, by stem, looked up in our own enumeration.
///
/// Windows PowerShell, not `pwsh`. It is present on every Windows machine, whereas
/// `pwsh` is frequently a `WindowsApps` execution-alias stub that would launch the
/// Store rather than a shell — which a read-only audit must not do.
const INTERPRETER_STEM: &str = "powershell";

/// Generous: the scan measures at about 210 ms on the machine this was written for.
/// The point is to refuse to hang, not to impose a budget.
const TIMEOUT: Duration = Duration::from_secs(10);

/// Field separator in the script's output. Built with `[char]9` so no escaping
/// convention has to survive the trip through the argument list.
const SEPARATOR: char = '\t';

/// Emits one line per construct: `kind`, name, and an alias's target.
///
/// A function's definition is its whole body, which may contain anything including
/// newlines, so it is deliberately not asked for — the name is the mask.
const SCRIPT: &str = "\
$ErrorActionPreference = 'SilentlyContinue'
$sep = [char]9
foreach ($a in Get-Command -CommandType Alias) {
    'alias' + $sep + $a.Name + $sep + $a.Definition
}
foreach ($f in Get-Command -CommandType Function) {
    'function' + $sep + $f.Name + $sep
}";

/// Ask a shell what it masks, and attach the answers to the names it masks.
///
/// Returns whether the scan actually ran. `false` means the caller must not claim
/// [`crate::Capability::ShellMasking`], because a `None` intercept would then be
/// indistinguishable from "not checked".
pub(crate) fn scan(executables: &mut [Resolved], mode: ShellScan) -> bool {
    let ShellScan::Ask { profile } = mode else {
        return false;
    };

    let Some(interpreter) = interpreter_path(executables) else {
        // No interpreter on PATH, so there is nothing to ask and nothing to claim.
        return false;
    };

    let Some(output) = run(&interpreter, profile) else {
        return false;
    };

    let constructs = parse(&output);
    for resolved in executables {
        if let Some((construct, resolves_to)) = constructs.get(&resolved.stem) {
            resolved.intercept = Some(Intercept {
                construct: *construct,
                resolves_to: resolves_to.clone(),
                interpreter: interpreter.clone(),
                profile_loaded: profile,
            });
        }
    }

    true
}

/// The absolute path of the interpreter, taken from our own enumeration.
fn interpreter_path(executables: &[Resolved]) -> Option<String> {
    let resolved = executables
        .iter()
        .find(|candidate| candidate.stem == INTERPRETER_STEM)?;

    // The copy this process would actually run, since that is the shell a user in
    // this session would get.
    let occurrence = resolved.live_winner().or_else(|| resolved.fresh_winner())?;

    let directory = occurrence.directory.trim_end_matches(['\\', '/']);
    Some(format!("{directory}\\{}", occurrence.file_name))
}

/// Run the script, giving up rather than hanging.
///
/// The read happens on another thread so a full pipe buffer cannot deadlock against
/// the timeout. On a timeout the child is left to finish on its own: this process is
/// about to produce a report and exit, and killing a shell mid-enumeration buys
/// nothing.
fn run(interpreter: &str, profile: bool) -> Option<String> {
    let mut command = Command::new(interpreter);
    if !profile {
        command.arg("-NoProfile");
    }
    command
        .arg("-NonInteractive")
        .arg("-Command")
        .arg(SCRIPT)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let _ = sender.send(command.output());
    });

    match receiver.recv_timeout(TIMEOUT) {
        Ok(Ok(output)) if output.status.success() => {
            // Names and cmdlet names are ASCII in practice, and a lossy decode of
            // something exotic is better than refusing to report at all.
            Some(String::from_utf8_lossy(&output.stdout).into_owned())
        }
        // A failed exit, a spawn error, or a timeout all mean the same thing here:
        // no answer, so claim nothing.
        _ => None,
    }
}

/// Index the script's output by lower-cased name.
///
/// An alias wins over a function of the same name, matching PowerShell's own
/// precedence, so the first entry for a name is kept.
fn parse(output: &str) -> HashMap<String, (ShellConstruct, Option<String>)> {
    let mut constructs = HashMap::new();

    for line in output.lines() {
        let mut fields = line.split(SEPARATOR);
        let (Some(kind), Some(name)) = (fields.next(), fields.next()) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }

        let construct = match kind {
            "alias" => ShellConstruct::Alias,
            "function" => ShellConstruct::Function,
            _ => continue,
        };

        let resolves_to = match construct {
            ShellConstruct::Alias => fields
                .next()
                .map(str::trim)
                .filter(|target| !target.is_empty())
                .map(str::to_owned),
            // A function is its own definition, not a redirection.
            ShellConstruct::Function => None,
        };

        constructs
            .entry(name.to_lowercase())
            .or_insert((construct, resolves_to));
    }

    constructs
}

#[cfg(test)]
mod tests {
    use super::{interpreter_path, parse, scan};
    use crate::{Occurrence, PathScope, Resolved, ShellConstruct, ShellScan};

    fn resolved(stem: &str, directory: &str, file_name: &str) -> Resolved {
        Resolved {
            stem: stem.to_owned(),
            occurrences: vec![Occurrence {
                entry_index: 0,
                scope: PathScope::Machine,
                process_position: Some(0),
                directory: directory.to_owned(),
                file_name: file_name.to_owned(),
                is_reparse_point: false,
            }],
            intercept: None,
        }
    }

    // ---- parsing, entirely portable ----

    #[test]
    fn an_alias_records_what_it_points_at() {
        let constructs = parse("alias\tsc\tSet-Content\n");

        assert_eq!(
            constructs.get("sc"),
            Some(&(ShellConstruct::Alias, Some("Set-Content".to_owned())))
        );
    }

    #[test]
    fn a_function_has_no_target_because_it_is_its_own_definition() {
        let constructs = parse("function\tmore\t\n");

        assert_eq!(
            constructs.get("more"),
            Some(&(ShellConstruct::Function, None))
        );
    }

    #[test]
    fn names_are_indexed_case_insensitively() {
        let constructs = parse("alias\tWhere\tWhere-Object\n");

        assert!(constructs.contains_key("where"));
        assert!(!constructs.contains_key("Where"));
    }

    #[test]
    fn an_alias_outranks_a_function_of_the_same_name() {
        // PowerShell's own precedence: alias, then function.
        let constructs = parse("alias\tls\tGet-ChildItem\nfunction\tls\t\n");

        assert_eq!(
            constructs.get("ls").map(|(construct, _)| *construct),
            Some(ShellConstruct::Alias)
        );
    }

    #[test]
    fn junk_lines_are_skipped_rather_than_guessed_at() {
        let constructs = parse(
            "\n\
             cmdlet\tGet-Item\tsomething\n\
             alias\t\tempty name\n\
             nonsense\n\
             alias\tgood\tGet-Item\n",
        );

        assert_eq!(constructs.len(), 1);
        assert!(constructs.contains_key("good"));
    }

    // ---- interpreter selection, entirely portable ----

    #[test]
    fn the_interpreter_is_named_by_absolute_path_from_our_own_enumeration() {
        // Not a fresh `PATH` search: the path comes from what this crate already
        // resolved, so it is the copy the audit itself vouched for.
        let executables = vec![
            resolved("git", r"C:\Program Files\Git\cmd", "git.exe"),
            resolved(
                "powershell",
                r"C:\WINDOWS\System32\WindowsPowerShell\v1.0",
                "powershell.exe",
            ),
        ];

        assert_eq!(
            interpreter_path(&executables),
            Some(r"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe".to_owned())
        );
    }

    #[test]
    fn a_trailing_separator_on_the_directory_is_not_doubled() {
        // `%SYSTEMROOT%\System32\WindowsPowerShell\v1.0\` really is stored with one.
        let executables = vec![resolved(
            "powershell",
            r"C:\WINDOWS\System32\WindowsPowerShell\v1.0\",
            "powershell.exe",
        )];

        assert_eq!(
            interpreter_path(&executables),
            Some(r"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe".to_owned())
        );
    }

    #[test]
    fn with_no_interpreter_on_path_there_is_nothing_to_ask() {
        let executables = vec![resolved("git", r"C:\Program Files\Git\cmd", "git.exe")];

        assert_eq!(interpreter_path(&executables), None);
    }

    // ---- the scan as a whole ----

    #[test]
    fn a_skipped_scan_claims_nothing() {
        let mut executables = vec![resolved("sc", r"C:\WINDOWS\system32", "sc.exe")];

        let ran = scan(&mut executables, ShellScan::Skip);

        assert!(!ran, "a skipped scan must not report itself as having run");
        assert!(executables[0].intercept.is_none());
    }

    #[test]
    fn a_scan_with_no_interpreter_claims_nothing() {
        let mut executables = vec![resolved("sc", r"C:\WINDOWS\system32", "sc.exe")];

        let ran = scan(&mut executables, ShellScan::Ask { profile: false });

        // No `powershell` in this list, so the scan cannot run — and must say so
        // rather than leaving a null intercept that reads as "not masked".
        assert!(!ran);
        assert!(executables[0].intercept.is_none());
    }

    #[test]
    fn the_real_shell_reports_its_own_built_in_aliases() {
        // Portable across Windows: `sc` for Set-Content and `where` for Where-Object
        // are built in, present without a profile, and both mask a real system32
        // executable.
        let interpreter = format!(
            r"{}\System32\WindowsPowerShell\v1.0",
            std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\WINDOWS".to_owned())
        );
        let mut executables = vec![
            resolved("powershell", &interpreter, "powershell.exe"),
            resolved("sc", r"C:\WINDOWS\system32", "sc.exe"),
            resolved("pathdoc-not-a-real-name", r"C:\nowhere", "nope.exe"),
        ];

        let ran = scan(&mut executables, ShellScan::Ask { profile: false });
        assert!(ran, "the scan should have run against {interpreter}");

        let Some(intercept) = &executables[1].intercept else {
            panic!("`sc` is a built-in alias and should have been reported")
        };
        assert_eq!(intercept.construct, ShellConstruct::Alias);
        assert_eq!(intercept.resolves_to.as_deref(), Some("Set-Content"));
        assert!(intercept.interpreter.ends_with("powershell.exe"));
        assert!(!intercept.profile_loaded);

        // A name nothing answers to stays clean, which is what makes the capability
        // flag meaningful rather than decorative.
        assert!(executables[2].intercept.is_none());
    }
}
