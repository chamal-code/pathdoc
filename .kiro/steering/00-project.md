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

**1b. Dependencies point at `winenv`, never from one tool at another.** Registry
access lives in its own crate that knows nothing about `PATH` — no `;`, no
machine-before-user, no notion of a directory. The env-var backup tool will depend
on `winenv`, **not** on `pathdoc-core`, which would drag `PathEntry`, `Resolved` and
`AuditReport` into a tool with no use for them. If something PATH-aware starts
creeping into `winenv`, it belongs in `pathdoc-core` instead.

`winenv` **stays in this repository** — decided, not open. No separate repo, no
crates.io. When the env-var tool exists, this repository becomes the toolkit
workspace and the tools join it as members. That bends the trunk's
one-repository-per-project convention, which predates a shared-library toolkit being
the plan; the trunk amends its own steering when the restructure happens, so do not
pre-empt it and do not "fix" the layout to match the old rule.

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

### Two sessions edit this machine — coordinate

Machine-level changes are the **trunk** session's responsibility, and the trunk
announces them. From this project session:

- **A red acceptance test means ask the trunk what changed.** Do not re-baseline
  blind, and do not guess at a cause — a plausible-sounding attribution that turns
  out to be wrong is worse than saying you do not know.
- **Never make machine-wide registry writes from here.** Not even to "fix" drift
  the tests just caught. Report it and let the trunk act.
- **Never adjust a number to make a test pass.** Find out what moved and why first.
  A baseline edited whenever reality disagrees is not a baseline.

Hit for real on **2026-09-16**, twice in one afternoon. At 17:48 the trunk appended
`%APPDATA%\fnm\aliases\default` to the user `PATH` while configuring an MCP server:
`npx.cmd` could not find `node`, because `fnm` only exposes it inside shells it has
activated. Two assertions failed within minutes. Later the same day GitHub CLI and
starship went into the machine scope, zoxide, just and dust into the user scope, and
the dead `Programs\Ollama` entry was pruned — shifting every user index by two.

Worth noting how the first one was misdiagnosed here: the added directory is a
symlink `fnm` created during provisioning, so `fnm` looked like the only plausible
owner. It was not; the write came from a session doing something else entirely. The
timestamps were consistent with a story that was wrong.

### Check the value kind as carefully as the value

```powershell
(Get-Item 'HKCU:\Environment').GetValueKind('Path')   # want ExpandString
(Get-Item 'HKCU:\Environment').GetValue('Path', $null, 'DoNotExpandEnvironmentNames')
```

`[Environment]::SetEnvironmentVariable` writes **`REG_SZ` unconditionally** — it is
not content-sensitive, whatever the common assumption. Confirmed by experiment:

```powershell
[Environment]::SetEnvironmentVariable('Probe', 'C:\literal', 'User')  # -> String
[Environment]::SetEnvironmentVariable('Probe', '%TEMP%\var', 'User')  # -> String
```

So every `PATH` edit through it silently downgrades `REG_EXPAND_SZ`. There is now an
assertion that every registry entry reports `REG_EXPAND_SZ`, which is the check that
catches it.

If a write slice is ever built: read with `DoNotExpandEnvironmentNames`, preserve
the value kind explicitly, and never round-trip through `SetEnvironmentVariable`.
Reading without that flag returns expanded paths, and writing those back turns an
indirection into a literal.

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
- **"Which copy wins" has two answers and they disagree.** Composed order is what a
  fresh process resolves by; the live process `PATH` is what the running one
  resolves by, and runtime injection goes to its *front*. Both are reported —
  `PathEntry::process_position` carries the live one, `None` when the process cannot
  see the directory at all. Rank resolution by live position, keep the composed
  index as it is. Do not "fix" this by interleaving process-only entries into the
  composed order: that would break the pinned indices for nothing.
- **A registry entry with no live position is not an error.** It is one the process
  started too early to see, and the only fix is a shell restart, which the table
  says out loud because nothing else in the report hints at it.
- **`just` on Windows runs recipes through `sh`, and the `sh` here is hermes'
  vendored MSYS shell.** It prepends `/mingw64/bin` and `/usr/bin`, so a recipe sees
  a different `PATH` from the shell that invoked it — with a second `git.exe` and
  `bash.exe` ahead of the real ones. It broke two acceptance assertions the first
  time `just check` ran. The `justfile` pins
  `set windows-shell := ["powershell.exe", "-NoProfile", "-Command"]`. Do not remove
  that line, and be suspicious of any tool that runs commands for you on this
  machine: the vendored `sh` is first on `PATH` and it rewrites the environment.
  `just probe-path` prints what a recipe actually sees, which is how this was found.
- **`set windows-shell`, never `set shell`.** `shell` overrides every platform, and
  the reason for pinning PowerShell is Windows-specific. `fmt-check` and `deny` are
  platform-independent, so a Linux runner in an OS matrix would try to spawn
  `powershell.exe` and fail.
- **Explanatory comments go above a recipe, not inside it.** `just` echoes each line
  of a recipe body, so an in-body `#` gets printed as though it were output. Put the
  long explanation above, then a single-line doc comment last, since `--list` shows
  only the final comment line.
- **Never assert a count that a harness can change.** Anything derived from the
  process `PATH` — how many entries are unseen, how many copies of a name exist — is
  a fact about the observing process. Assert relationships instead:
  `fresh_winner()` ignores process-only directories and so is harness-independent,
  and composed indices come from the registry, which no harness touches.
- **`winget`'s installers append a trailing `;`.** That is where the `Empty` finding
  on this machine keeps coming from. It does not accumulate — always exactly one or
  none — and edits that rebuild the value from a filtered split remove it again.
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
- **Shadowing does not gate the exit code.** `system32` alone ships eight names
  under two extensions apiece, so counting shadowing would leave exit 1 permanently
  on, and a signal that is always on is not a signal. Exit 1 is for the per-entry
  findings, which are things a person can go and fix. `--fail-on-shadow` is the
  opt-in for anyone who wants it gate-worthy.
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

## Use the justfile

`just check` is the gate here: `fmt-check`, `clippy` in both feature configurations,
the tests including the machine-specific ones, then `cargo deny check`. It is what
`project.manifest.json` points at, so both sessions and a human have one entry
point that cannot drift from the docs.

**CI must use `just check-portable`, not `just check`.** `check` runs the acceptance
tests via `--run-ignored all` and so fails anywhere that is not this machine.
`check-portable` is the same gate with `test-portable` in place of `test`.

### The CI split is forced, not a preference

`.github/workflows/check.yml` runs the full portable gate on `windows-latest` and
only `fmt-check` and `deny` on `ubuntu-latest`.

**Do not add a Linux build or test job.** This workspace cannot be compiled for
Linux: `executables.rs` uses `std::os::windows::fs::MetadataExt` to read file
attributes without following reparse points, and `winenv` depends on `winreg`. A
Linux build fails for a reason unrelated to the code being wrong, and "fixing" it
would mean giving up reparse-point detection, which is a spec requirement.

The Linux job is not decoration: it is the only thing that exercises
`set windows-shell`, since with `set shell` those two recipes would try to spawn
`powershell.exe` on Ubuntu.

One trap when adding a `pwsh` step: the step fails if `$LASTEXITCODE` is non-zero
when the script ends, and `pathdoc` exits 1 whenever it reports findings — which is
the normal case. Capture the code, check it, and end with an explicit `exit 0`.

`pathdoc-core` must stay clean **without** the `serde` feature as well as with it,
because a GUI linking the library may not want serde and that configuration is not
otherwise built. `just lint` covers both; a bare `cargo clippy` does not.

## How the tests are laid out

Worth knowing before adding one:

| Where | Kind | Rule |
| --- | --- | --- |
| `crates/*/src/*.rs`, `mod tests` | unit | Portable. Every input explicit, including the environment lookup. |
| `crates/pathdoc-core/tests/this_machine.rs` | acceptance | Machine-specific on purpose. All `#[ignore]`. |
| `crates/pathdoc-cli/src/json.rs`, `mod tests` | contract | Pins field names and enum tags. Breaking the JSON contract must break a test. |

The acceptance tests are `#[ignore]`d so a stranger's `cargo test` on a fresh clone
passes and reports 19 skipped, which is the correct answer off this machine. They
still gate here, because `just test` passes `--run-ignored all`.

**Both halves are load-bearing.** Do not strip the `#[ignore]` attributes to tidy up
a skipped count, and do not drop `--run-ignored all` from the justfile to make an
outside clone greener — that would leave the drift canary outside the gate, which is
a canary nobody looks at. Any new test in that file needs the attribute too:

```rust
#[test]
#[ignore = "machine-specific: see `just test-machine`"]
```

`just test-portable` is the stranger's view, for checking the public experience
without leaving this machine.

Renderer tests write into an `anstream::StripStream` over a buffer, so assertions
read as the plain text a user sees while production still emits real ANSI. One
mechanism, not two.
