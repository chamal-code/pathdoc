# pathdoc — project steering

Project-specific rules. Global steering in `~/.kiro/steering/` is inherited; do
not duplicate it here.

## The two rules that matter

**1. The core crate never prints.** `pathdoc-core` returns data structures.
Every `println!`, colour code and column width belongs to `pathdoc-cli`. This is
what keeps a shared GUI able to link the library directly instead of shelling out
and parsing text — and the GUI is confirmed, not hypothetical. If a function in
core needs to format something for display, it is in the wrong crate.

The one carve-out, decided deliberately: **serialisation is not formatting.** The
`serde` derives and the `JsonReport` envelope live in core behind a `serde`
feature, because the wire shape is the same contract whether it travels as Rust
types over a direct link or as JSON over a pipe, and two definitions of one
contract drift. Do not "fix" this by moving the derives into the CLI. What would
genuinely breach rule 1 is a `Display` impl, a label, or a column width on a
report type.

**2. This tool is read-only.** No registry writes, no PATH edits, no fix mode,
not even behind a flag. A tool that audits PATH and a tool that edits PATH have
very different blast radii, and the second one needs a design for backups,
dry-run and confirmation before any code is written. Do not let it creep in.
`crates/pathdoc-cli/src/options.rs` has a test that rejects `--fix`, `--write`,
`--repair`, `--remove` and `--dedupe`, because the way this erodes is a flag
landing before the design does.

## Verification is concrete here

The expected findings on this machine were established by hand during
provisioning on 2026-09-15 and are written into `docs/SPEC.md` under
Verification. **All six are now covered** by
`crates/pathdoc-core/tests/this_machine.rs`: one dead `Ollama` entry, three
`git.exe` with `Program Files` winning, vendored `gzip`/`bash`/`unzip`/`sdiff`,
`python` from `~\.local\bin` with no `WindowsApps` stub, `uv` twice with
`WinGet\Links` winning, and the `fnm_multishells` entry **not** flagged.

That file is deliberately machine-specific and will fail anywhere else. Keep new
machine-specific assertions in it and keep the unit tests portable — inputs
supplied explicitly, including the environment lookup, so no machine's layout
leaks into the logic.

**`this_machine.rs` is the only place the expected numbers live.** Do not copy them
into prose. They were briefly duplicated across `docs/SPEC.md`, `README.md` and the
machine's toolchain steering, and went stale in all three within a day.

### When it fails, the machine changed — go and look

Hit for real on **2026-09-16**: something appended
`%APPDATA%\fnm\aliases\default` to `HKCU\Environment\Path` and rewrote the value as
`REG_SZ` where it had been `REG_EXPAND_SZ`, taking the user scope from 14 entries to
15. Two assertions failed within minutes of the change, before anyone noticed
otherwise.

The rule that falls out of it: **never adjust a number in this file to make it
pass.** Find out what moved and why first. A baseline that gets edited whenever
reality disagrees is not a baseline. Useful when investigating:

```powershell
(Get-Item 'HKCU:\Environment').GetValueKind('Path')
(Get-Item 'HKCU:\Environment').GetValue('Path', $null, 'DoNotExpandEnvironmentNames')
```

The value **kind** is worth checking as carefully as the value. A tool rewriting
`REG_EXPAND_SZ` as `REG_SZ` is silent and harmless right up until somebody adds a
`%VAR%` to the PATH.

Cross-check against `Get-Command <name> -All`, which is the independent
reference. Remember it also returns aliases and functions: `diff` and `fc` are
PowerShell aliases on this machine, not programs, and shell-level masking is
explicitly a later slice. Composition order already cross-checks itself against
PowerShell at test time; shadowing does not, and automating it is on the roadmap.

## Gotchas already known

- Compose PATH as **machine first, then user**. Getting this backwards inverts
  every shadowing verdict.
- Read `PATHEXT` from the environment; do not hard-code the list.
- Distinguish `REG_SZ` from `REG_EXPAND_SZ`. A literal `%USERPROFILE%` and an
  expanded one are different facts.
- Process-only entries are normal, not errors. `fnm` injects a per-shell shim
  directory on activation.
- **Process-only entries are appended after the registry block, which makes their
  shadowing rank wrong for the live shell.** Runtime injection usually goes at the
  *front* of the process `PATH`, so a name present in both a process-only directory
  and a registry one is reported with the wrong winner. Live example since
  2026-09-16: `node` is reported as resolving from `fnm\aliases\default` (a registry
  entry) when in an `fnm` shell it actually comes from `fnm_multishells`. Recorded
  as an open question in `docs/SPEC.md`; the fix is to track each entry's live
  process position. Do not "fix" it by interleaving, which would break the pinned
  indices.
- Report reparse points rather than following them, so Store alias stubs stay
  identifiable. Live examples of both branches: `WinGet\Links\uv.exe` **is** a
  symlink, `~\.local\bin\python.exe` is not.
- **`cargo test` pollutes the process `PATH` of the test binary.** It prepends
  `target\debug`, `target\debug\deps` and two toolchain directories, so a test
  sees four more process-only entries than the shell that launched it. Hit while
  writing `tests/this_machine.rs`, which originally asserted one process-only
  entry and found five. Never assert a *count* of process-only entries from
  inside a test; name the directory you care about. The binary run directly
  reports 23 entries, `cargo run` reports 27.
- **`PATHEXT` here is twelve entries, not the documented eleven.** It ends in
  `.CPL`, and `system32` holds `powercfg.cpl` next to `powercfg.exe`. This is the
  concrete reason the list is read from the environment.
- **Strip only the matched `PATHEXT` extension from a name.** `python3.11.exe` is
  the program `python3.11`, not `python3`. Both exist in `~\.local\bin`, so
  getting this wrong merges two real programs.
- **Resolution has two loops, not one.** `PATH` order between directories,
  `PATHEXT` order within one. `read_dir` returns files in filesystem order, which
  is not `PATHEXT` order — `system32` lists `winrm.vbs` before `winrm.cmd` and the
  `.cmd` is what runs. Sort explicitly.
- **Enumerate a directory once.** An entry carrying `Duplicate` is skipped,
  because an earlier entry names the same directory and reading it twice reports
  every program in it as shadowing itself.
- **`executables` is never empty on a real machine.** Testing it for emptiness to
  decide "were there findings" makes every run exit non-zero. Ask whether anything
  is *contested* instead. There is a test named for this trap in
  `crates/pathdoc-cli/src/main.rs`.
- **Nothing on this `PATH` denies enumeration**, so `Unreadable` has no live
  example. Its test denies itself read on a temp directory with `icacls` and
  restores the ACE on drop. It prints a skip notice if the deny does not apply,
  so a machine where it could not be verified does not look like one where it was.

## Test fixtures

`.gitattributes` marks `tests/fixtures/**` and `crates/**/tests/fixtures/**` as
`binary`. **No fixture directory exists yet** — the rule is pre-emptive, and slice
1 turned out not to need one. Every test either supplies its inputs inline or
creates real files in a temp directory it cleans up.

Keep the rule anyway. If a fixture with CRLF, a lone CR, or NUL bytes ever lands,
git normalising it would make the test meaningless, and that is exactly the kind of
failure that wastes an afternoon. Do not relax it, and do not assume fixtures
exist because the rule does.

## How the tests are laid out

Worth knowing before adding one:

| Where | Kind | Rule |
| --- | --- | --- |
| `crates/*/src/*.rs`, `mod tests` | unit | Portable. Every input explicit, including the environment lookup. |
| `crates/pathdoc-core/tests/this_machine.rs` | acceptance | Machine-specific on purpose. Expected to fail elsewhere. |
| `crates/pathdoc-cli/src/json.rs`, `mod tests` | contract | Pins field names and enum tags. Breaking the JSON contract must break a test. |

Renderer tests write into an `anstream::StripStream` over a buffer, so assertions
read as the plain text a user sees while production still emits real ANSI. One
mechanism, not two.
