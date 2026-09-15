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

Explicit, and important for slice 1:

- **It never writes.** No PATH edits, no registry writes, no "fix it for me".
  Mutation is a later slice, if ever, and would require its own design for
  backups and confirmation.
- Not a `which` replacement. It audits the whole PATH rather than resolving one name.
- No GUI. The core crate stays presentation-free so a GUI can consume it later.

## Slice 1 scope

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

Group by stem, case-insensitively, since Windows resolution is case-insensitive.
Where a stem appears in more than one entry, report the winner and every shadowed
copy in order. Also flag when a single directory holds the same stem under several
extensions, because `foo.com` beats `foo.exe` by `PATHEXT` order and that surprises
people.

Reparse points get reported as such rather than followed, so a `WindowsApps`
alias stub is distinguishable from a real binary.

### Output

Human-readable table by default. `--json` emits the same data as a stable,
documented shape — this is the contract a future GUI consumes, so it is part of
the spec, not an afterthought.

Flags for slice 1:

```
pathdoc [--json] [--scope machine|user|all] [--shadows-only] [--no-color]
```

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Audit ran, nothing worth reporting |
| 1 | Audit ran, findings present |
| 2 | Fatal error: registry unreadable, bad arguments |

Matching the convention already used across this machine's tooling.

## Verification

The acceptance test is unusually concrete, because the expected answers were
established by hand during provisioning. On this machine, slice 1 must:

- report exactly one dead entry, `...\AppData\Local\Programs\Ollama`
- report three `git.exe`, with `C:\Program Files\Git\cmd` winning
- report the vendored `gzip.exe`, `bash.exe`, `unzip.exe`, `sdiff.exe`
- report `python.exe` resolving from `~\.local\bin`, with no `WindowsApps` stub
  remaining
- report `uv.exe` twice, with `...\WinGet\Links` winning
- **not** flag the `fnm_multishells` process-only entry as an error

Cross-check shadowing against PowerShell's own resolver, which is the
independent reference:

```powershell
Get-Command git -All | Select-Object -ExpandProperty Source
```

Note that `Get-Command` also returns aliases and functions, which are shell
constructs rather than PATH entries — `diff` and `fc` are PowerShell aliases on
this machine, not programs. Slice 1 audits PATH only; alias masking is noted
in the roadmap below because it is a genuinely different mechanism.

## Roadmap

Deliberately out of slice 1:

1. **Shell-level masking.** Report when a PATH executable is unreachable because
   the shell resolves the name to an alias or function first. `diff` and `fc` are
   live examples. Needs per-shell introspection, so it is its own slice.
2. **App Execution Aliases.** Decode `WindowsApps` reparse points to the owning
   package, so a Store stub is named rather than merely flagged.
3. **Env var backup & diff.** PATH is one variable; the registry layer built here
   generalises. Intended as the next tool in the workspace, sharing `pathdoc-core`'s
   registry module.
4. **Fix mode.** Only after backup, dry-run and confirmation are designed properly.

## Design constraint carried across the whole toolkit

`pathdoc-core` returns data structures and never prints. All formatting, colour
and ordering for display belongs to `pathdoc-cli`. This is what makes a shared GUI
possible later without shelling out and scraping text.
