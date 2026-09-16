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
use std::io::{BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::{Intercept, Interpreter, Resolved, ShellConstruct, ShellScan};

/// Interpreter asked when the caller names none, by stem, looked up in our own
/// enumeration.
///
/// Windows PowerShell, not `pwsh`. It is present on every Windows machine, whereas
/// `pwsh` is frequently a `WindowsApps` execution-alias stub that would launch the
/// Store rather than a shell — which a read-only audit must not do.
const DEFAULT_INTERPRETER: &str = "powershell";

/// Generous: the scan measures at about 150 ms on the machine this was written for.
/// The point is to refuse to hang, not to impose a budget.
///
/// It was 10 seconds, and a GitHub Actions runner exceeded it. Raising it is a hedge
/// rather than a fix — any fixed value can be exceeded on a loaded machine — so the
/// script below was made cheaper at the same time, which is the actual remedy.
const TIMEOUT: Duration = Duration::from_secs(30);

/// How often to check whether the child has finished.
const POLL: Duration = Duration::from_millis(25);

/// How long to wait for the reader once the child has exited and closed the pipe.
const DRAIN: Duration = Duration::from_secs(2);

/// Field separator in the script's output. Built with `[char]9` so no escaping
/// convention has to survive the trip through the argument list.
const SEPARATOR: char = '\t';

/// Emits one line per construct: `kind`, name, and an alias's target.
///
/// A function's definition is its whole body, which may contain anything including
/// newlines, so it is deliberately not asked for — the name is the mask.
///
/// `Get-Alias` and the `Function:` drive, deliberately, and **not**
/// `Get-Command -CommandType Alias,Function`. `Get-Command` walks every module path
/// to enumerate commands that autoloading *could* provide, which on this machine is
/// 1391 constructs against 197, and is the kind of work that balloons on a cold
/// machine with a different module inventory. Measured here at 218 ms against 149 ms,
/// and — the part that matters — both find exactly the same 24 masked names, with no
/// difference in either direction. The expensive enumeration bought nothing and was
/// the likeliest reason a CI runner blew a 10-second timeout.
const SCRIPT: &str = "\
$ErrorActionPreference = 'SilentlyContinue'
$sep = [char]9
foreach ($a in Get-Alias) {
    'alias' + $sep + $a.Name + $sep + $a.Definition
}
foreach ($f in Get-ChildItem Function:) {
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
    scan_with(executables, mode, requested, run)
}

/// [`scan`], with the subprocess injected.
///
/// The seam exists so the parsing, deduplication, capability and multiple-interpreter
/// logic can be tested against canned output with no shell involved. Asserting that a
/// live interpreter answers is a machine assumption, and machine assumptions belong in
/// `this_machine.rs` — a portable test that spawns a shell is a portable test that
/// fails on a slow machine, which is how CI found this.
fn scan_with<F>(
    executables: &mut [Resolved],
    mode: ShellScan,
    requested: &[String],
    ask: F,
) -> Vec<Interpreter>
where
    F: Fn(&str, bool) -> Option<String>,
{
    let ShellScan::Ask { profile } = mode else {
        return Vec::new();
    };

    let mut consulted: Vec<Interpreter> = Vec::new();

    for choice in resolve_choices(executables, requested) {
        let Some(output) = ask(&choice, profile) else {
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

/// Turn the caller's choices into distinct absolute interpreter paths.
///
/// Deduplicated **here, before anything is spawned**. The first version deduplicated
/// against the list of interpreters that had already answered, which meant a repeated
/// name spawned a second time whenever the first attempt failed — two timeouts instead
/// of one. CI showed it as a 20-second test where every other timeout was 10.
fn resolve_choices(executables: &[Resolved], requested: &[String]) -> Vec<String> {
    let candidates: Vec<Option<String>> = if requested.is_empty() {
        vec![interpreter_path(executables, DEFAULT_INTERPRETER)]
    } else {
        requested
            .iter()
            .map(|choice| {
                if looks_like_a_path(choice) {
                    // Taken at face value: the caller asked for this exact file.
                    Some(choice.clone())
                } else {
                    interpreter_path(executables, &choice.to_lowercase())
                }
            })
            .collect()
    };

    let mut paths: Vec<String> = Vec::new();
    for path in candidates.into_iter().flatten() {
        if !paths.iter().any(|seen| seen.eq_ignore_ascii_case(&path)) {
            paths.push(path);
        }
    }

    paths
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

/// Run the script, giving up rather than hanging, and **never leaving a child behind**.
///
/// The earlier version handed the whole `Command` to a thread and called `output()`,
/// which meant there was no handle to kill: on timeout the shell was abandoned. That
/// is shipped behaviour, not a test artifact — a long-lived consumer such as a GUI
/// would accumulate one orphaned shell per audit on any machine slow enough to trip
/// the timeout. CI found it as a `LEAK` on a test that *passed*.
///
/// So the child is spawned here and held. Reading still happens on another thread,
/// because polling for exit without draining the pipe would deadlock the child once
/// the buffer filled — the deadlock the previous version correctly avoided.
fn run(interpreter: &str, profile: bool) -> Option<String> {
    let mut command = Command::new(interpreter);
    if !profile {
        command.arg("-NoProfile");
    }
    command.arg("-NonInteractive").arg("-Command").arg(SCRIPT);

    run_command(command, TIMEOUT)
}

/// Supervise one child: read it, time it out, and kill it rather than abandon it.
///
/// Split from [`run`] with the timeout as a parameter so the kill path can be tested.
/// It cannot be tested through `run`, because the scan takes about 150 ms against a
/// 30-second timeout, so the interesting branch never executes on a healthy machine —
/// which is precisely why the leak shipped and only CI saw it.
fn run_command(mut command: Command, timeout: Duration) -> Option<String> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let mut child = command.spawn().ok()?;

    let Some(stdout) = child.stdout.take() else {
        terminate(&mut child);
        return None;
    };

    // The reader owns the pipe and nothing else. It is deliberately not joined: once
    // `terminate` or a normal exit has reaped the child, the write end is closed and
    // `read_to_end` returns, so the thread is bounded without the caller waiting on
    // it. Joining would risk blocking a report on a grandchild that inherited the
    // handle, and this crate produces reports rather than managing process trees.
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut buffer = Vec::new();
        let read = BufReader::new(stdout).read_to_end(&mut buffer);
        let _ = sender.send(read.map(|_| buffer));
    });

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            // Exited on its own, so there is nothing to kill either way.
            Ok(Some(status)) => {
                if !status.success() {
                    return None;
                }
                break;
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    terminate(&mut child);
                    return None;
                }
                thread::sleep(POLL);
            }
            Err(_) => {
                terminate(&mut child);
                return None;
            }
        }
    }

    // The child has gone, so the pipe is closed and the reader is finishing.
    match receiver.recv_timeout(DRAIN) {
        // Names and cmdlet names are ASCII in practice, and a lossy decode of
        // something exotic beats refusing to report at all.
        Ok(Ok(bytes)) => Some(String::from_utf8_lossy(&bytes).into_owned()),
        // A read error or a reader that never finished is no answer, so claim nothing.
        _ => None,
    }
}

/// Kill a child and reap it.
///
/// The `wait` is not optional: without it the process stays a zombie and the pipe's
/// write end may stay open, which would leave the reader thread blocked forever — the
/// leak this function exists to prevent, moved one step along.
fn terminate(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
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
    use super::{interpreter_path, parse, resolve_choices, run_command, scan_with};
    use crate::{Occurrence, PathScope, Resolved, ShellConstruct, ShellScan};
    use std::cell::RefCell;
    use std::thread;
    use std::time::Duration;

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

    // ---- the scan as a whole, against an injected interpreter ----
    //
    // No subprocess. Whether a live shell answers is a property of the machine, and a
    // portable test that spawns one is a portable test that fails on a slow machine —
    // which is exactly how CI found the timeout bug. The single real-shell test lives
    // in `this_machine.rs`, where a machine assumption belongs, and skips loudly.

    /// Records every interpreter it was asked about, so a test can assert how many
    /// times a shell would have been spawned.
    struct FakeShell {
        asked: RefCell<Vec<(String, bool)>>,
        answers: Vec<(String, String)>,
    }

    impl FakeShell {
        /// `answers` maps a path suffix to the canned script output for it.
        fn new(answers: &[(&str, &str)]) -> Self {
            Self {
                asked: RefCell::new(Vec::new()),
                answers: answers
                    .iter()
                    .map(|(path, output)| ((*path).to_owned(), (*output).to_owned()))
                    .collect(),
            }
        }

        fn ask(&self, interpreter: &str, profile: bool) -> Option<String> {
            self.asked
                .borrow_mut()
                .push((interpreter.to_owned(), profile));
            self.answers
                .iter()
                .find(|(path, _)| interpreter.eq_ignore_ascii_case(path))
                .map(|(_, output)| output.clone())
        }

        fn asked_paths(&self) -> Vec<String> {
            self.asked
                .borrow()
                .iter()
                .map(|(path, _)| path.clone())
                .collect()
        }
    }

    const FIVE: &str = r"C:\WINDOWS\ps\powershell.exe";
    const SEVEN: &str = r"C:\pwsh7\pwsh.exe";

    fn two_shells() -> Vec<Resolved> {
        vec![
            resolved("powershell", r"C:\WINDOWS\ps", "powershell.exe"),
            resolved("pwsh", r"C:\pwsh7", "pwsh.exe"),
            resolved("sc", r"C:\WINDOWS\system32", "sc.exe"),
            resolved("curl", r"C:\WINDOWS\system32", "curl.exe"),
            resolved("where", r"C:\WINDOWS\system32", "where.exe"),
        ]
    }

    #[test]
    fn a_skipped_scan_consults_nobody_and_spawns_nothing() {
        let mut executables = vec![resolved("sc", r"C:\WINDOWS\system32", "sc.exe")];
        let shell = FakeShell::new(&[]);

        let consulted = scan_with(&mut executables, ShellScan::Skip, &[], |path, profile| {
            shell.ask(path, profile)
        });

        assert!(
            consulted.is_empty(),
            "a skipped scan must not report an interpreter as consulted"
        );
        assert!(
            shell.asked_paths().is_empty(),
            "a skipped scan must not spawn anything"
        );
        assert!(executables[0].intercepts.is_empty());
    }

    #[test]
    fn a_scan_with_no_interpreter_on_path_consults_nobody() {
        let mut executables = vec![resolved("sc", r"C:\WINDOWS\system32", "sc.exe")];
        let shell = FakeShell::new(&[(FIVE, "alias\tsc\tSet-Content\n")]);

        let consulted = scan_with(
            &mut executables,
            ShellScan::Ask { profile: false },
            &[],
            |path, profile| shell.ask(path, profile),
        );

        // No `powershell` in the enumeration, so there is nothing to ask — and nothing
        // may be claimed, or empty `intercepts` would read as "nothing masks it".
        assert!(consulted.is_empty());
        assert!(shell.asked_paths().is_empty());
        assert!(executables[0].intercepts.is_empty());
    }

    #[test]
    fn the_same_interpreter_named_twice_is_spawned_once() {
        // The dedup bug: it used to be keyed on interpreters that had already
        // *answered*, so a repeat spawned again whenever the first attempt failed.
        // Asserting the spawn count is what makes that visible; asserting only the
        // result would pass either way.
        let mut executables = two_shells();
        let shell = FakeShell::new(&[]);

        let consulted = scan_with(
            &mut executables,
            ShellScan::Ask { profile: false },
            &["powershell".to_owned(), "POWERSHELL".to_owned()],
            |path, profile| shell.ask(path, profile),
        );

        assert!(consulted.is_empty(), "the fake refuses to answer");
        assert_eq!(
            shell.asked_paths(),
            vec![FIVE.to_owned()],
            "a repeated name must be deduplicated before anything is spawned"
        );
    }

    #[test]
    fn an_interpreter_that_does_not_answer_is_not_reported_as_consulted() {
        let mut executables = two_shells();
        let shell = FakeShell::new(&[(FIVE, "alias\tsc\tSet-Content\n")]);

        let consulted = scan_with(
            &mut executables,
            ShellScan::Ask { profile: false },
            &["powershell".to_owned(), "pwsh".to_owned()],
            |path, profile| shell.ask(path, profile),
        );

        // Both were tried; only one answered, so only one may be listed. Every name
        // therefore stays *unknown* for pwsh rather than clear.
        assert_eq!(shell.asked_paths(), vec![FIVE.to_owned(), SEVEN.to_owned()]);
        assert_eq!(consulted.len(), 1);
        assert_eq!(consulted[0].path, FIVE);
    }

    #[test]
    fn an_explicit_path_is_asked_without_needing_an_enumeration_entry() {
        // The `--shell C:\...` route.
        let mut executables = vec![resolved("sc", r"C:\WINDOWS\system32", "sc.exe")];
        let shell = FakeShell::new(&[(r"D:\custom\pwsh.exe", "alias\tsc\tSet-Content\n")]);

        let consulted = scan_with(
            &mut executables,
            ShellScan::Ask { profile: false },
            &[r"D:\custom\pwsh.exe".to_owned()],
            |path, profile| shell.ask(path, profile),
        );

        assert_eq!(consulted.len(), 1);
        assert_eq!(consulted[0].path, r"D:\custom\pwsh.exe");
        assert_eq!(executables[0].intercepts.len(), 1);
    }

    #[test]
    fn the_profile_choice_reaches_the_interpreter_and_the_record() {
        let mut executables = two_shells();
        let shell = FakeShell::new(&[(FIVE, "alias\tsc\tSet-Content\n")]);

        let consulted = scan_with(
            &mut executables,
            ShellScan::Ask { profile: true },
            &[],
            |path, profile| shell.ask(path, profile),
        );

        assert!(
            shell.asked.borrow()[0].1,
            "the profile flag must reach the interpreter"
        );
        assert!(consulted[0].profile_loaded);
        let Some(sc) = executables.iter().find(|r| r.stem == "sc") else {
            panic!("sc missing from the fixture")
        };
        assert!(sc.intercepts[0].profile_loaded);
    }

    // ---- process supervision: the timeout must kill, not abandon ----
    //
    // Uses `cmd.exe` rather than PowerShell, by absolute path. Nothing here is about
    // shells or aliases; it is about not leaking a child, and cmd is on every Windows
    // machine and starts faster.

    fn cmd_exe() -> String {
        format!(
            r"{}\System32\cmd.exe",
            std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\WINDOWS".to_owned())
        )
    }

    #[test]
    fn a_child_that_finishes_in_time_has_its_output_returned() {
        let mut command = std::process::Command::new(cmd_exe());
        command.arg("/c").arg("echo pathdoc-ok");

        let Some(output) = run_command(command, Duration::from_secs(10)) else {
            eprintln!("skipped: cmd.exe did not run, so supervision was not exercised");
            return;
        };

        assert!(output.contains("pathdoc-ok"), "got {output:?}");
    }

    #[test]
    fn a_child_that_overruns_the_timeout_is_killed_and_not_abandoned() {
        // The bug this proves fixed. Previously the whole `Command` went to a thread
        // and `output()` was called, so there was no handle to kill and the child was
        // left running — one orphaned shell per audit in any consumer that outlives a
        // single report, such as the GUI this library exists to serve. CI reported it
        // as a LEAK on a test that passed.
        //
        // The child sleeps, then writes a marker. Killed, the marker never appears;
        // abandoned, it appears once the sleep finishes. So the marker's absence after
        // the sleep would have elapsed is the proof.
        //
        // Note what is *not* claimed: `kill` terminates `cmd.exe`, not the `ping`
        // grandchild it spawned. The marker is written by cmd, so a dead cmd is enough
        // to prove the point — and the surviving grandchild is the concrete reason
        // `run_command` does not join its reader thread.
        let marker = std::env::temp_dir().join(format!(
            "pathdoc-kill-proof-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let _ = std::fs::remove_file(&marker);

        // `ping` is the portable Windows sleep: roughly two seconds for `-n 3`. The
        // two margins point in opposite directions and both are deliberately wide.
        // The sleep must comfortably outlast the 200 ms timeout or the kill path never
        // runs, and it must finish comfortably before the check below or a merely slow
        // machine reads as a pass. 200 ms against 2 s against 5 s gives an order of
        // magnitude on one side and more than double on the other.
        let script = format!(
            "ping -n 3 127.0.0.1 >nul & echo abandoned> \"{}\"",
            marker.display()
        );
        let mut command = std::process::Command::new(cmd_exe());
        command.arg("/c").arg(&script);

        let outcome = run_command(command, Duration::from_millis(200));

        assert!(
            outcome.is_none(),
            "a child that overran its timeout must not be reported as having answered"
        );

        // Well past when the child would have written the marker had it survived.
        thread::sleep(Duration::from_secs(5));

        let abandoned = marker.exists();
        let _ = std::fs::remove_file(&marker);
        assert!(
            !abandoned,
            "the child outlived its timeout and wrote {}; it was abandoned, not killed",
            marker.display()
        );
    }

    #[test]
    fn one_name_masked_in_one_shell_and_clear_in_another() {
        // The case the plural shape exists for, deterministically: `curl` is an alias
        // in Windows PowerShell and the real binary in PowerShell 7, `where` is masked
        // in both, and `sc` only in the first.
        let mut executables = two_shells();
        let shell = FakeShell::new(&[
            (
                FIVE,
                "alias\tsc\tSet-Content\nalias\tcurl\tInvoke-WebRequest\nalias\twhere\tWhere-Object\n",
            ),
            (SEVEN, "alias\twhere\tWhere-Object\n"),
        ]);

        let consulted = scan_with(
            &mut executables,
            ShellScan::Ask { profile: false },
            &["powershell".to_owned(), "pwsh".to_owned()],
            |path, profile| shell.ask(path, profile),
        );

        assert_eq!(consulted.len(), 2);

        let find = |stem: &str| {
            executables
                .iter()
                .find(|r| r.stem == stem)
                .unwrap_or_else(|| panic!("{stem} missing"))
                .clone()
        };

        // Masked in one, and clear in the other — which is a verdict only because both
        // interpreters are in the consulted list.
        let curl = find("curl");
        assert!(curl.intercept_by(FIVE).is_some());
        assert!(curl.intercept_by(SEVEN).is_none());

        let both = find("where");
        assert!(both.intercept_by(FIVE).is_some());
        assert!(both.intercept_by(SEVEN).is_some());
        assert_eq!(both.intercepts.len(), 2);

        let sc = find("sc");
        assert_eq!(sc.intercepts.len(), 1);
    }
}
