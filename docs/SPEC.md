# pathdoc — specification

A read-only auditor for the Windows `PATH`. It answers three questions that
Windows itself makes awkward to answer:

1. Which directories are on `PATH`, in the order Windows actually resolves them?
2. Which of those entries are dead, duplicated, or redundant?
3. When two directories both contain `foo.exe`, which one wins, and what is hidden?

## Why this exists

Provisioning this machine on 2026-09-15 turned up a pile of PATH problems that
took manual archaeology to find:

- `git` resolved to a copy vendored inside a retired application's folder
- a second vendored `git` was hiding inside a different application's folder
- `gzip`, `bash`, `unzip` and `sdiff` all resolved into that same application
- `python` resolved to a Microsoft Store alias stub that only opened the Store
- our own `uv` lost to a vendored `uv` because of user-PATH ordering
- one entry, `...\Programs\Ollama`, does not exist on disk at all

Every one of those was found by hand. This tool exists so the next person does
not have to.

## Non-goals

Explicit, and load-bearing:

- **It never writes.** No PATH edits, no registry writes, no "fix it for me".
  Mutation is a later slice, if ever, and would require its own design for
  backups and confirmation.
- Not a `which` replacement. It audits the whole PATH rather than resolving one
  name on request. This is why the table reports contested names only and leaves
  the full list of around a thousand to `--json`: there is deliberately no
  `pathdoc <name>` verb.
- **No GUI in this repository.** A GUI is a confirmed future consumer, but it
  lives elsewhere and links `pathdoc-core` directly. That is the whole reason the
  core crate stays presentation-free.

## Slice 1 scope

**Status: complete.** Everything in this section is implemented and covered by
tests. See Verification below for what that means concretely on this machine, and
the Roadmap for what was deliberately left out.

### Reading PATH

Read from the **registry**, not the process environment:

| Scope | Key |
| --- | --- |
| Machine | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment` |
| User | `HKCU\Environment` |

Compose them the way Windows does: **machine entries first, then user entries.**
That ordering is the whole reason Git for Windows outranked the vendored copies
on this machine without any intervention, so getting it right is the point.

Record whether each value was `REG_SZ` or `REG_EXPAND_SZ`, and report both the
literal and expanded form when they differ. An entry stored as
`%USERPROFILE%\.cargo\bin` is not the same fact as one stored expanded.

Also read the process `PATH` and report entries present there but in neither
registry scope. Those are injected at runtime — `fnm`'s per-shell shim directory
is a legitimate example and must not be reported as an error.

### Per-entry findings

| Finding | Meaning |
| --- | --- |
| `Missing` | Directory does not exist |
| `NotADirectory` | Path exists but is a file |
| `Duplicate` | Same canonical path appears earlier in the composed order |
| `Empty` | Empty segment, usually a stray `;` |
| `Relative` | Not an absolute path; resolution depends on the current directory |
| `Unreadable` | Exists but enumeration failed, e.g. denied by ACL |

### Shadowing

For every entry, enumerate executables. "Executable" means the file extension
appears in `PATHEXT` (default `.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC`),
compared case-insensitively. Read `PATHEXT` from the environment rather than
hard-coding it.

That last point is not pedantry. On this machine `PATHEXT` is
`.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL` — one entry longer
than the documented default — and `system32` holds `powercfg.cpl` beside
`powercfg.exe`. Hard-coding the default would have missed it.

Group by stem, case-insensitively, since Windows resolution is case-insensitive.
Only the matched extension comes off the name, so `python3.11.exe` is the program
`python3.11` and not `python3`.

Resolution order is `PATH` order first, then `PATHEXT` order within a single
directory — both loops, because the inner one is the part people forget. Report
every place a name resolves from, in that order, so `occurrences[0]` is the copy
that wins. Flag separately when every occurrence sits in the *same* directory,
because then `PATHEXT` decided it and no amount of reordering `PATH` will help:
`winrm.cmd` beats `winrm.vbs` in `system32`, whatever order the filesystem lists
them in.

A directory that appears twice on `PATH` is enumerated once. The later entry
already carries a `Duplicate` finding, and reading it again would report every
program in it as shadowing itself.

Reparse points get reported as such rather than followed, so a `WindowsApps`
alias stub is distinguishable from a real binary. Verified live on this machine:
`WinGet\Links\uv.exe` is a symlink into the package directory and is reported as
one, while `~\.local\bin\python.exe` is a real binary and is not.

### Output

Human-readable table by default. `--json` emits a stable, documented shape — the
contract a GUI consumes, so it is part of the spec, not an afterthought.

The two are not identical, deliberately. The table shows the composition, the
per-entry findings, and the **contested** executable names; `--json` additionally
carries every name found. A human scanning a terminal and a program building a
searchable view want different amounts of the same audit.

Flags:

```
pathdoc [--json] [--scope machine|user|all] [--shadows-only] [--no-color]
```

`--scope` and `--shadows-only` filter what is **reported**. They never change how
`PATH` is composed, and entries keep the index they hold in the full composed
order — `--scope user` on this machine starts at index 8, not 0. A renumbered
index would throw away the one thing composition order is for.

Colour is decided by `anstream`: it honours `NO_COLOR` and `CLICOLOR`, checks
whether the destination is a terminal, and turns on virtual terminal processing
where Windows needs it. `--no-color` forces it off regardless.

### The JSON contract

`--json` is what a GUI consumes, so the shape is versioned and the field names are
fixed. The types are defined once in `pathdoc-core` and derive their
serialisation there, behind a `serde` feature, so a front end that links the
library and one that parses this output cannot drift apart.

```json
{
  "schemaVersion": 2,
  "capabilities": ["composition", "entryFindings", "shadowDetection"],
  "entries": [
    {
      "index": 0,
      "scope": "machine",
      "raw": "%SystemRoot%\\system32",
      "expanded": "C:\\WINDOWS\\system32",
      "valueKind": "REG_EXPAND_SZ",
      "findings": []
    }
  ],
  "executables": [
    {
      "stem": "git",
      "occurrences": [
        {
          "entryIndex": 7,
          "directory": "C:\\Program Files\\Git\\cmd",
          "fileName": "git.exe",
          "isReparsePoint": false
        }
      ]
    }
  ]
}
```

Rules the shape follows:

- **camelCase** field names, matching the trunk's other JSON.
- `scope` is `machine`, `user` or `processOnly`.
- `valueKind` is `REG_SZ`, `REG_EXPAND_SZ`, or `null` for an entry that came from
  no registry value at all. The real registry type names, because whoever reads
  this is likely to have `regedit` open next to it.
- `expanded` is `null` rather than absent when there was nothing to expand, so a
  typed consumer gets `string | null` and not `string | undefined`. The
  directory Windows actually resolves is `expanded ?? raw`. That is deliberately
  not its own field: a derived field in a wire shape is a field that can
  contradict the two it derives from.
- `findings` entries are a discriminated union on `kind`: `{"kind": "missing"}`,
  `{"kind": "duplicate", "firstSeenAt": 0}`.
- `executables` holds **every** name found, sorted by stem, not only the contested
  ones — around a thousand on an ordinary machine. `occurrences` is in resolution
  order, so `occurrences[0]` is the one that wins, and a name is shadowed when
  there is more than one. See the note on schema 2 below for why it is not filtered.
- `occurrences[].directory` is denormalised rather than left as a join on
  `entryIndex`. `entries` may be a filtered subset, or empty under
  `--shadows-only`, and an occurrence that cannot be understood without an array
  that might not be present is not much of a fact.
- `executables` is **never** filtered by `--scope`. Which copy of a name wins is
  decided across the whole `PATH`, so a scope-narrowed answer would be wrong
  rather than merely narrower.
- `capabilities` says what the run actually computed. **An empty `executables`
  means "nothing found" only when `shadowDetection` is listed; otherwise it means
  "not computed".** Without this a consumer shows a clean bill of health for work
  that never ran, which is worse than showing nothing.
- `schemaVersion` bumps only on a breaking change: a field removed or renamed, an
  enum representation altered, or an existing field's meaning changed. Adding a
  field, a variant, or a capability is additive and does not bump it.

The assertions pinning all of the above live in `crates/pathdoc-cli/src/json.rs`,
so breaking the contract breaks a test.

#### Why schema 2 replaced `shadows` with `executables`

Schema 1 had a `shadows` array holding only names that resolve from more than one
place. That could not satisfy this spec's own acceptance criteria. Of the four
executables listed under Verification below, **three — `gzip`, `unzip` and
`sdiff` — appear exactly once**, as does `python`. A conflicts-only array could
never have named them, and "`gzip` comes out of a chat client's private folder" is
exactly the kind of fact this tool exists to surface.

So the report carries every name it found and a consumer filters. `shadows` was
the wrong shape, not a wrong implementation of the right shape.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Audit ran, nothing worth reporting |
| 1 | Audit ran, findings present |
| 2 | Fatal error: registry unreadable, bad arguments |

Matching the convention already used across this machine's tooling. The code
describes what was **reported**, not what the audit saw, so `--scope machine`
exits 0 while the only dead entry is in the user scope. That keeps the flag
composable in a script rather than a lie waiting to happen.

A closed pipe is not an error. `pathdoc | head` exits 0.

#### Open question: process-only entries are ranked last, not where they really sit

Composed order puts registry entries first and appends process-only entries after
them. That was needed to make the pinned indices work — index 0 is `system32`,
index 7 is `Git\cmd`, index 8 is the first user entry — and it is defensible as
"the composition Windows would build for a fresh process".

It is also **wrong about which copy wins** whenever a name exists in both a
process-only directory and a registry one, because runtime injection usually goes
at the *front* of the live `PATH`, not the back.

There is now a live example, courtesy of the 2026-09-16 change described under
Verification. `node`, `npm`, `npx` and `corepack` exist in both
`%APPDATA%\fnm\aliases\default` (a registry entry, index 22) and
`...\fnm_multishells\<pid>_<ts>` (process-only, index 23). pathdoc reports the
registry copy as the winner. In an `fnm`-activated shell the shim wins, because it
sits at live position 0:

```powershell
Get-Command node -All | Where-Object CommandType -eq Application
# ...\fnm_multishells\20244_1789497930171\node.exe
```

So pathdoc's answer is right for a fresh non-`fnm` process and wrong for the shell
you are probably typing in. Before the change it never mattered, because `node`
appeared exactly once.

The fix is to record each entry's position in the live process `PATH` — `None` when
it is absent from it — and rank resolution by that where it exists, falling back to
the composed index. The composed index stays as it is, so the pinned indices and
the JSON contract survive. **Not done**, because it changes what
`occurrences[0]` means and that deserves a deliberate decision rather than a quiet
patch.

#### Open question: shadowing makes exit 1 the normal case

As specified, a contested executable name is a finding, so it produces exit 1.
That is what this table and the original `has_findings` both said, and it is what
is implemented.

In practice it makes the exit code close to useless as a health signal. `system32`
alone ships eight names under two extensions apiece — `eventvwr`, `perfmon`,
`services`, `hdwwiz`, `powercfg`, `manage-bde`, `SyncAppvPublishingServer`,
`winrm` — so a machine with nothing but `system32` on its `PATH` still exits 1.
On this machine dozens of names are contested and not one of them is a defect.

The alternative is to let only per-entry findings drive the exit code and treat
shadowing as informational, which would make exit 1 mean "something is actually
wrong with your PATH". **Undecided.** Changing it is a one-line change in
`reported_findings` plus this table, and it is a behavioural break for anything
scripting against the current codes, so it should be decided rather than drift.

## Verification

The acceptance test is unusually concrete, because the expected answers were
established by hand during provisioning. On this machine, slice 1 must:

- [x] report exactly one dead entry, `...\AppData\Local\Programs\Ollama`
- [x] report three `git.exe`, with `C:\Program Files\Git\cmd` winning
- [x] report the vendored `gzip.exe`, `bash.exe`, `unzip.exe`, `sdiff.exe`
- [x] report `python.exe` resolving from `~\.local\bin`, with no `WindowsApps` stub
  remaining
- [x] report `uv.exe` twice, with `...\WinGet\Links` winning
- [x] **not** flag the `fnm_multishells` process-only entry as an error

All six are covered by `crates/pathdoc-core/tests/this_machine.rs`, which also
pins the composition itself — 8 machine entries, 14 user, 22 composed,
`C:\WINDOWS\system32` at index 0 stored as `%SystemRoot%\system32`,
`C:\Program Files\Git\cmd` at index 7, the first user entry at index 8 — and the
`PATHEXT`, versioned-shim and reparse-point behaviour described above.

`this_machine.rs` is the **single source of truth** for the expected numbers.
Earlier drafts of this file, the README and the machine's toolchain steering all
repeated them in prose, which meant four places to update and three of them
silently wrong the moment the machine changed. They now point here instead.

Nothing on this `PATH` refuses to enumerate, so `Unreadable` has no live example
and is covered by a test that denies itself read on a temporary directory instead.

### The baseline moves, and that is the test's job to notice

On **2026-09-16 at 17:48** something appended
`%APPDATA%\fnm\aliases\default` to `HKCU\Environment\Path` and rewrote the value
as `REG_SZ` where it had been `REG_EXPAND_SZ`. The user scope went from 14 entries
to 15. Nobody asked for it and the change has not been attributed; the directory
is a symlink `fnm` created during provisioning the day before, so `fnm` is the only
plausible owner, but the write itself is unexplained.

Two tests failed immediately, which is exactly what they are for. Treat a failure
in this file as "the machine changed, go and find out why" — never as a number to
adjust until the cause is understood. The `REG_SZ` part matters more than the extra
entry: nothing in the user `PATH` uses `%VAR%` today, so it is harmless now, but a
`REG_SZ` value will not expand one if somebody adds it later.

### Independent cross-checks

Composition order is cross-checked **automatically**. `this_machine.rs` shells out
to PowerShell and compares both registry scopes against
`[Environment]::GetEnvironmentVariable('Path', 'Machine'|'User')`, which reads the
same two values by a completely different route. Expected values are not
hard-coded for that test; they are queried at run time.

Shadowing is **not** cross-checked automatically — the assertions there are
against values established by hand. PowerShell remains the reference for a spot
check:

```powershell
Get-Command git -All | Select-Object -ExpandProperty Source
```

Note that `Get-Command` also returns aliases and functions, which are shell
constructs rather than PATH entries — `diff` and `fc` are PowerShell aliases on
this machine, not programs. This tool audits PATH only; alias masking is in the
roadmap below because it is a genuinely different mechanism.

Automating that comparison is a reasonable future addition: `Get-Command -All`
filtered to `CommandType -eq 'Application'` should agree with a name's
`occurrences`, in order. It was left out because reconciling PowerShell's own
`PATHEXT` handling and alias entries is a fair amount of test machinery for a
check that hand verification already passed.

## Roadmap

Deliberately out of slice 1, in no particular order:

1. **Shell-level masking.** Report when a PATH executable is unreachable because
   the shell resolves the name to an alias or function first. `diff` and `fc` are
   live examples. Needs per-shell introspection, so it is its own slice.
2. **App Execution Aliases.** Decode `WindowsApps` reparse points to the owning
   package, so a Store stub is named rather than merely flagged. Slice 1 reports
   *that* a file is a reparse point but never *what* it points at, by design —
   `WinGet\Links\uv.exe` is a live example.
3. **Env var backup & diff.** PATH is one variable; the registry layer built here
   generalises. Intended as the next tool in the workspace, sharing
   `pathdoc-core`'s registry module — which is currently `mod registry`, private,
   so this needs the module made public or lifted into a crate of its own. Worth
   deciding which before a second tool depends on it.
4. **Fix mode.** Only after backup, dry-run and confirmation are designed properly.
5. **Automated shadowing cross-check** against `Get-Command -All`, as described
   above.
6. **Settle the exit-code question** in the Open question section above.

## Design constraint carried across the whole toolkit

`pathdoc-core` returns data structures and never prints. All formatting, colour
and ordering for display belongs to `pathdoc-cli`. This is what makes a shared GUI
possible later without shelling out and scraping text.

**Serialisation is not formatting**, and the `serde` derives in `pathdoc-core` are
not a breach of that rule. A wire schema is a data representation, and defining it
once on the real types is what stops a linked GUI and a JSON consumer from
drifting apart. What would breach the rule is a column width, a colour code, or a
human-readable label appearing in the core. `Display` implementations for report
types belong in the front end, not on the types.
