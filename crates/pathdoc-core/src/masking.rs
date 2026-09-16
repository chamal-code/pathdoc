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

use crate::{Intercept, Interpreter, Resolved, ShellConstruct, ShellScan};

/// Interpreter asked when the caller names none, by stem, looked up in our own
/// enumeration.
///
/// Windows PowerShell, not `pwsh`. It is present on every Windows machine, whereas
/// `pwsh` is frequently a `WindowsApps` execution-alias stub that would launch the
/// Store rather than a shell — which a read-only audit must not do.
const DEFAULT_INTERPRETER: &str = "powershell";

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

/// Ask each requested shell what it masks, and attach the answers.
///
/// Returns the interpreters that actually answered. An empty list means the caller
/// must not claim [`crate::Capability::ShellMasking`], because empty `intercepts`
/// would then be indistinguishable from "not checked".
///
/// The returned list is what makes an absent record meaningful. Consulted and absent
/// from a name means that interpreter is clear for that name; not consulted means
/// nobody knows.
pub(crate) fn scan(
    executables: &mut [Resolved],
    mode: ShellScan,
    requested: &[String],
) -> Vec<Interpreter> {
    let ShellScan::Ask { profile } = mode else {
        return Vec::new();
    };

    let mut consulted: Vec<Interpreter> = Vec::new();

    for choice in resolve_choices(executables, requested) {
        // A repeat would only produce a duplicate answer.
        if consulted
            .iter()
            .any(|already| already.path.eq_ignore_ascii_case(&choice))
        {
            continue;
        }

        let Some(output) = run(&choice, profile) else {
            // No answer, so it is not recorded as consulted, and every name stays
            // "unknown" for this interpreter rather than "clear".
            continue;
        };

        let constructs = parse(&output);
        for resolved in executables.iter_mut() {
            if let Some((construct, resolves_to)) = constructs.get(&resolved.stem) {
                resolved.intercepts.push(Intercept {
                    construct: *construct,
                    resolves_to: resolves_to.clone(),
                    interpreter: choice.clone(),
                    profile_loaded: profile,
                });
            }
        }

        consulted.push(Interpreter {
            path: choice,
            profile_loaded: profile,
        });
    }

    consulted
}

/// Turn the caller's choices into absolute interpreter paths.
fn resolve_choices(executables: &[Resolved], requested: &[String]) -> Vec<String> {
    if requested.is_empty() {
        return interpreter_path(executables, DEFAULT_INTERPRETER)
            .into_iter()
            .collect();
    }

    requested
        .iter()
        .filter_map(|choice| {
            if looks_like_a_path(choice) {
                // Taken at face value: the caller asked for this exact file.
                Some(choice.clone())
            } else {
                interpreter_path(executables, &choice.to_lowercase())
            }
        })
        .collect()
}

/// Whether a choice is a path rather than a stem to look up.
fn looks_like_a_path(choice: &str) -> bool {
    choice.contains('\\') || choice.contains('/')
}

/// The absolute path of an interpreter, taken from our own enumeration.
///
/// Deliberately not a fresh `PATH` search. Looking the stem up in what this crate
/// already resolved means the interpreter is one the audit itself vouched for.
fn interpreter_path(executables: &[Resolved], stem: &str) -> Option<String> {
    let resolved = executables
        .iter()
        .find(|candidate| candidate.stem == stem)?;

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
    use super::{interpreter_path, parse, resolve_choices, scan};
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
            intercepts: Vec::new(),
        }
    }

    /// Windows PowerShell's real location, for the tests that spawn it.
    fn windows_powershell_dir() -> String {
        format!(
            r"{}\System32\WindowsPowerShell\v1.0",
            std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\WINDOWS".to_owned())
        )
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
            interpreter_path(&executables, "powershell"),
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
            interpreter_path(&executables, "powershell"),
            Some(r"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe".to_owned())
        );
    }

    #[test]
    fn with_no_interpreter_on_path_there_is_nothing_to_ask() {
        let executables = vec![resolved("git", r"C:\Program Files\Git\cmd", "git.exe")];

        assert_eq!(interpreter_path(&executables, "powershell"), None);
    }

    // ---- choosing which interpreters to ask ----

    #[test]
    fn with_no_choice_the_default_interpreter_is_asked() {
        let executables = vec![
            resolved("git", r"C:\Program Files\Git\cmd", "git.exe"),
            resolved("powershell", r"C:\WINDOWS\ps", "powershell.exe"),
        ];

        assert_eq!(
            resolve_choices(&executables, &[]),
            vec![r"C:\WINDOWS\ps\powershell.exe".to_owned()]
        );
    }

    #[test]
    fn a_stem_is_looked_up_in_the_enumeration_rather_than_searched_for() {
        // The point: the interpreter is one this audit already resolved, not the
        // result of a second `PATH` search inside a tool built to distrust them.
        let executables = vec![
            resolved("powershell", r"C:\WINDOWS\ps", "powershell.exe"),
            resolved("pwsh", r"C:\Program Files\PowerShell\7", "pwsh.exe"),
        ];

        assert_eq!(
            resolve_choices(&executables, &["pwsh".to_owned()]),
            vec![r"C:\Program Files\PowerShell\7\pwsh.exe".to_owned()]
        );
    }

    #[test]
    fn an_explicit_path_is_taken_at_face_value() {
        // The caller named a file rather than a name to resolve, so no lookup.
        let executables = vec![resolved("powershell", r"C:\WINDOWS\ps", "powershell.exe")];

        assert_eq!(
            resolve_choices(&executables, &[r"D:\custom\pwsh.exe".to_owned()]),
            vec![r"D:\custom\pwsh.exe".to_owned()]
        );
    }

    #[test]
    fn a_stem_that_is_not_on_path_is_dropped_rather_than_guessed_at() {
        let executables = vec![resolved("powershell", r"C:\WINDOWS\ps", "powershell.exe")];

        // `pwsh` is not installed, so it is simply not consulted — and therefore
        // never appears in `interpreters_consulted`, which is what keeps "unknown"
        // distinct from "clear".
        assert!(resolve_choices(&executables, &["pwsh".to_owned()]).is_empty());
    }

    #[test]
    fn several_interpreters_can_be_asked() {
        let executables = vec![
            resolved("powershell", r"C:\WINDOWS\ps", "powershell.exe"),
            resolved("pwsh", r"C:\pwsh7", "pwsh.exe"),
        ];

        assert_eq!(
            resolve_choices(&executables, &["powershell".to_owned(), "pwsh".to_owned()]),
            vec![
                r"C:\WINDOWS\ps\powershell.exe".to_owned(),
                r"C:\pwsh7\pwsh.exe".to_owned(),
            ]
        );
    }

    // ---- the scan as a whole ----

    #[test]
    fn a_skipped_scan_consults_nobody() {
        let mut executables = vec![resolved("sc", r"C:\WINDOWS\system32", "sc.exe")];

        let consulted = scan(&mut executables, ShellScan::Skip, &[]);

        assert!(
            consulted.is_empty(),
            "a skipped scan must not report an interpreter as consulted"
        );
        assert!(executables[0].intercepts.is_empty());
    }

    #[test]
    fn a_scan_with_no_interpreter_consults_nobody() {
        let mut executables = vec![resolved("sc", r"C:\WINDOWS\system32", "sc.exe")];

        let consulted = scan(&mut executables, ShellScan::Ask { profile: false }, &[]);

        // No `powershell` in this list, so nothing can be asked — and nothing may be
        // claimed, or an empty `intercepts` would read as "nothing masks it".
        assert!(consulted.is_empty());
        assert!(executables[0].intercepts.is_empty());
    }

    #[test]
    fn the_same_interpreter_named_twice_is_asked_once() {
        let interpreter = windows_powershell_dir();
        let mut executables = vec![
            resolved("powershell", &interpreter, "powershell.exe"),
            resolved("sc", r"C:\WINDOWS\system32", "sc.exe"),
        ];

        let consulted = scan(
            &mut executables,
            ShellScan::Ask { profile: false },
            &["powershell".to_owned(), "powershell".to_owned()],
        );

        assert_eq!(consulted.len(), 1, "consulted: {consulted:?}");
        assert_eq!(
            executables[1].intercepts.len(),
            1,
            "`sc` should be reported once, not once per repeat"
        );
    }

    #[test]
    fn the_real_shell_reports_its_own_built_in_aliases() {
        // Portable across Windows: `sc` for Set-Content and `where` for Where-Object
        // are built in, present without a profile, and both mask a real system32
        // executable.
        let interpreter = windows_powershell_dir();
        let mut executables = vec![
            resolved("powershell", &interpreter, "powershell.exe"),
            resolved("sc", r"C:\WINDOWS\system32", "sc.exe"),
            resolved("pathdoc-not-a-real-name", r"C:\nowhere", "nope.exe"),
        ];

        let consulted = scan(&mut executables, ShellScan::Ask { profile: false }, &[]);
        assert_eq!(
            consulted.len(),
            1,
            "the scan should have consulted {interpreter}"
        );
        assert!(consulted[0].path.ends_with("powershell.exe"));
        assert!(!consulted[0].profile_loaded);

        let [intercept] = executables[1].intercepts.as_slice() else {
            panic!(
                "`sc` is a built-in alias and should have exactly one intercept, got {:?}",
                executables[1].intercepts
            )
        };
        assert_eq!(intercept.construct, ShellConstruct::Alias);
        assert_eq!(intercept.resolves_to.as_deref(), Some("Set-Content"));
        assert!(intercept.interpreter.ends_with("powershell.exe"));
        assert!(!intercept.profile_loaded);

        // A name nothing answers to stays clear. Combined with the interpreter being
        // in the consulted list, that is a real verdict rather than a gap.
        assert!(executables[2].intercepts.is_empty());
    }

    #[test]
    fn an_explicit_path_to_the_real_shell_also_works() {
        // The `--shell` route: a caller naming a file rather than a name to resolve.
        let path = format!(r"{}\powershell.exe", windows_powershell_dir());
        let mut executables = vec![resolved("sc", r"C:\WINDOWS\system32", "sc.exe")];

        let consulted = scan(
            &mut executables,
            ShellScan::Ask { profile: false },
            std::slice::from_ref(&path),
        );

        assert_eq!(consulted.len(), 1);
        assert_eq!(consulted[0].path, path);
        // And no `powershell` entry was needed in the enumeration for it.
        assert_eq!(executables[0].intercepts.len(), 1);
    }

    #[test]
    fn an_interpreter_that_cannot_be_run_is_not_reported_as_consulted() {
        let mut executables = vec![resolved("sc", r"C:\WINDOWS\system32", "sc.exe")];

        let consulted = scan(
            &mut executables,
            ShellScan::Ask { profile: false },
            &[r"C:\pathdoc\no-such-shell.exe".to_owned()],
        );

        // Nothing answered, so every name stays unknown for it rather than clear.
        assert!(consulted.is_empty());
        assert!(executables[0].intercepts.is_empty());
    }
}
