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

On `Empty` specifically, because it turned up repeatedly on this machine and the
cause was not obvious: **winget's installers append a trailing `;`** when they add
a package directory. It does not accumulate — five `PATH` backups taken across
2026-09-16 showed exactly one empty segment or none, never two, so a single
separator is being re-added rather than compounding. Edits that rebuild the value
from a filtered split remove it again, so it appears and disappears depending on
which happened last.
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
every place a name resolves from, in that order. Flag separately when every
occurrence sits in the *same* directory,
because then `PATHEXT` decided it and no amount of reordering `PATH` will help:
`winrm.cmd` beats `winrm.vbs` in `system32`, whatever order the filesystem lists
them in.

A directory that appears twice on `PATH` is enumerated once. The later entry
already carries a `Duplicate` finding, and reading it again would report every
program in it as shadowing itself.

#### Two orderings, because there are two questions

"Which copy wins" has two different correct answers and they routinely disagree.

Composed order — machine then user, process-only appended — is what a **newly
started process** resolves by. The live process `PATH` is what **this process**
resolves by, and runtime injection goes to the *front* of it, not the back. So a
per-shell shim beats a registry entry now and loses to it after a restart.

Both are reported. Every entry carries its position in the live process `PATH`, or
`null` when the process cannot see it at all — which is what a registry entry added
since the process started looks like. Occurrences are ranked by live position, with
unreachable ones last, and the fresh-process winner is reported alongside whenever
it differs.

**How many entries a process can or cannot see is a property of that process, not
of the machine, and must never be asserted as a machine fact.** Three observers
disagreed on one afternoon and all three were right: a shell started before a batch
of installs saw seven registry entries as unreachable; a long-lived shell that had
been assigned `$env:Path = machine + ';' + user` saw none, having dropped the
injected shim while keeping `FNM_MULTISHELL_PATH` set, which is impossible in a
clean shell; and a `cargo test` binary sees four extra directories cargo prepends.
The ordering *arithmetic* is unit-tested against synthetic `PATH` values where both
sides are controlled; the acceptance test only confirms the mechanism exists.

The live example, since 2026-09-16: `node`, `npm`, `npx` and `corepack` sit in both
`%APPDATA%\fnm\aliases\default`, a registry entry, and `...\fnm_multishells\<id>`,
which is process-only. Cross-check:

```powershell
Get-Command node -All | Where-Object CommandType -eq Application
# ...\fnm_multishells\20244_1789497930171\node.exe   <- what runs now
```

Before that change no name existed in both kinds of directory, so a single ordering
looked sufficient. It was not.

A registry entry the running process cannot see is reported plainly, with the only
fix there is: restart the shell.

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
pathdoc [--json] [--scope machine|user|all] [--shadows-only] [--fail-on-shadow]
        [--shell-scan off|no-profile|profile] [--no-color]
```

`--shell-scan` defaults to `no-profile`, which sees built-in aliases and functions and
has no side effects. `profile` is the only way to see a user's own aliases and makes
this tool **execute arbitrary user code** while producing a read-only report, so it is
opt-in. `off` spawns nothing.

`--shell` chooses which interpreter to ask and may be repeated. A bare name such as
`pwsh` is looked up in the audit's own results, so the interpreter is one the report
vouches for; a value containing a separator is taken as a literal path. It defaults to
Windows PowerShell. A named interpreter that cannot be found or will not answer is
simply not consulted, and therefore never appears in `interpretersConsulted` — which
keeps "unknown" distinct from "clear".

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
  "schemaVersion": 4,
  "capabilities": ["composition", "entryFindings", "shadowDetection", "shellMasking"],
  "entries": [
    {
      "index": 0,
      "scope": "machine",
      "raw": "%SystemRoot%\\system32",
      "expanded": "C:\\WINDOWS\\system32",
      "valueKind": "REG_EXPAND_SZ",
      "processPosition": 1,
      "findings": []
    }
  ],
  "interpretersConsulted": [
    {
      "path": "C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "profileLoaded": false
    }
  ],
  "executables": [
    {
      "stem": "sc",
      "intercepts": [
        {
          "construct": "alias",
          "resolvesTo": "Set-Content",
          "interpreter": "C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          "profileLoaded": false
        }
      ],
      "occurrences": [
        {
          "entryIndex": 0,
          "scope": "machine",
          "processPosition": 1,
          "directory": "C:\\WINDOWS\\system32",
          "fileName": "sc.exe",
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
- `processPosition` is the entry's index in the **live process** `PATH`, or `null`
  when the running process cannot see that directory at all. `null` is not an
  error: it is what a registry entry added since the process started looks like.
- `executables` holds **every** name found, sorted by stem, not only the contested
  ones — around a thousand on an ordinary machine. A name is shadowed when it has
  more than one occurrence. See the note on schema 2 below for why it is not
  filtered.
- `occurrences` is in **live** resolution order: copies the running process can
  reach first, in process order, then copies it cannot, in composed order. Derive
  the two winners like this, which is exactly what the library does:

  | Question | Rule |
  | --- | --- |
  | What runs now? | first occurrence whose `processPosition` is not `null` |
  | What would run in a new process? | lowest `entryIndex` among occurrences whose `scope` is not `processOnly` |

  They disagree whenever runtime injection is involved, and a verdict that does not
  say which one it means is not much use.
- `occurrences[].directory`, `scope` and `processPosition` are denormalised rather
  than left as a join on `entryIndex`. `entries` may be a filtered subset, or empty
  under `--shadows-only`, and an occurrence that cannot be understood without an
  array that might not be present is not much of a fact. Carrying all three is also
  what makes the table above computable from the JSON alone.
- `executables` is **never** filtered by `--scope`. Which copy of a name wins is
  decided across the whole `PATH`, so a scope-narrowed answer would be wrong
  rather than merely narrower.
- `intercepts` is what shells answer to that name **before `PATH` is searched**, one
  record per interpreter that masks it, `[]` for none. `construct` is `alias` or
  `function`; `resolvesTo` is an alias's target and `null` for a function, which is
  its own definition rather than a redirection; `interpreter` is an **absolute path**,
  never a shell name.
- `interpretersConsulted` is the other half of reading `intercepts`, and it is what
  makes an absent record mean something. With two shells asked, a name carrying no
  record for one of them is otherwise ambiguous — asked and clear, or never asked?
  **Listed there and absent from a name's `intercepts` means asked and clear.** Not
  listed means nobody knows. Empty `intercepts` means "nothing masks it" only when
  `shellMasking` is in `capabilities`.

  Measured on this machine with both shells consulted, which is why the field is a
  list rather than a single record:

  | Name | Windows PowerShell 5.1 | PowerShell 7 |
  | --- | --- | --- |
  | `curl` | alias for `Invoke-WebRequest` | clear, runs `curl.exe` |
  | `sc` | alias for `Set-Content` | clear, runs `sc.exe` |
  | `where`, `fc`, `ls` | masked | masked |
- `capabilities` says what the run actually computed. **An empty `executables`
  means "nothing found" only when `shadowDetection` is listed; otherwise it means
  "not computed".** The same applies to a `null` `intercept` and `shellMasking`.
  Without this a consumer shows a clean bill of health for work that never ran, which
  is worse than showing nothing.
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

#### Why schema 4 added `intercepts` and `interpretersConsulted`

Shell-level masking. Purely additive — nothing removed or renamed — and it extends the
per-name records rather than becoming a new section or a `Finding`, for the reasons
under Shell-level masking above.

`intercepts` is plural from the outset. A singular field would have worked for one
interpreter and had to become a list the first time two were consulted, and `curl`
being masked in 5.1 and clear in 7 made that certain rather than hypothetical — a
schema version spent on something foreseeable. This project has already spent two on
shape corrections (2 and 3); the third was avoidable while nothing consumed the
contract, so it was avoided.

The CI workflow asserts the schema version, so a bump has to be made in the same
commit as the change. That friction is the check working.

#### Why schema 3 added `processPosition`

Ranking resolution by composed index named the wrong winner for any name present
in both a process-only directory and a registry one, because runtime injection goes
to the front of the live `PATH` rather than the back. See "Two orderings" above.
Nothing was removed: the composed `index` still means what it always did, so the
pinned indices and every existing field survived the bump.

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

#### Only actionable findings gate the exit code

A contested executable name is **not** a failure. Shadowing is usually correct and
intentional, and `system32` alone ships eight names under two extensions apiece —
`eventvwr`, `perfmon`, `services`, `hdwwiz`, `powercfg`, `manage-bde`,
`SyncAppvPublishingServer`, `winrm` — so a machine with nothing but `system32` on
its `PATH` would exit 1. A signal that is always on is not a signal.

Exit 1 is reserved for the per-entry findings, which are all things a person can go
and fix: `Missing`, `NotADirectory`, `Duplicate`, `Empty`, `Relative`,
`Unreadable`. Shadowing is always reported and never gates, unless asked:

```
pathdoc --fail-on-shadow
```

Which is the flag to use in CI for a machine whose `PATH` is supposed to be
pristine.

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

Those 19 tests are all `#[ignore]`d, so a fresh clone elsewhere passes and skips
them — the assertions describe one machine's registry and a stranger has a different
one. They still run on every gate here, because `just test` passes
`--run-ignored all`. Excluding them outright would have been simpler and would have
put the drift canary outside the gate.

`this_machine.rs` is the **single source of truth** for the expected numbers.
Earlier drafts of this file, the README and the machine's toolchain steering all
repeated them in prose, which meant four places to update and three of them
silently wrong the moment the machine changed. They now point here instead.

Nothing on this `PATH` refuses to enumerate, so `Unreadable` has no live example
and is covered by a test that denies itself read on a temporary directory instead.

### The baseline moves, and that is the test's job to notice

Two agent sessions edit this machine. Machine-wide changes are the trunk
session's responsibility and the trunk announces them, so **a red acceptance test
means ask the trunk what changed** before touching anything. Never make
machine-wide registry writes from the project session.

It has earned its keep. On **2026-09-16 at 17:48** the trunk appended
`%APPDATA%\fnm\aliases\default` to `HKCU\Environment\Path` while configuring an
MCP server: `npx.cmd` could not find `node`, because `fnm` only exposes it inside
shells it has activated, and putting the default-alias directory on `PATH` is the
fix. Two tests failed within minutes. Later the same day GitHub CLI and starship
went into the machine scope and zoxide, just and dust into the user scope, and the
dead `Programs\Ollama` entry was pruned — which shifted every user index by two.

The lesson is not "expect churn". It is that a baseline is only worth having if it
is never edited to make it pass.

#### `SetEnvironmentVariable` downgrades the value kind

The same session's edits rewrote the user `PATH` as `REG_SZ` where it had been
`REG_EXPAND_SZ`. Root cause, confirmed by experiment:

```powershell
[Environment]::SetEnvironmentVariable('Probe', 'C:\literal',  'User')  # -> String
[Environment]::SetEnvironmentVariable('Probe', '%TEMP%\var',  'User')  # -> String
```

It writes `REG_SZ` **unconditionally**. It is not content-sensitive, which is the
common assumption. Five `PATH` edits used it that day and each one silently
downgraded the kind. It was restored afterwards, and there is now an assertion
that every registry entry reports `REG_EXPAND_SZ` — the check that would have
caught it.

Harmless in the moment, because nothing in the user `PATH` uses `%VAR%`. Not
harmless later: a `REG_SZ` value will not expand the first one somebody adds.

Anything that ever writes `PATH` — the fix-mode slice, if it happens — must read
with `DoNotExpandEnvironmentNames`, preserve the value kind explicitly, and never
round-trip through `SetEnvironmentVariable`. Reading without that flag returns
expanded paths, and writing those back replaces an indirection with a literal.

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

1. **`--fail-on-mask`**, if anybody actually asks for it. Not built: a flag with no
   user is a guess about the future. Shell-level masking detection, multiple
   interpreters and `--shell` are all done and specified above.
2. **App Execution Aliases.** Decode `WindowsApps` reparse points to the owning
   package, so a Store stub is named rather than merely flagged. Slice 1 reports
   *that* a file is a reparse point but never *what* it points at, by design —
   `WinGet\Links\uv.exe` is a live example.
3. **Env var backup & diff.** PATH is one variable; the registry layer generalises,
   and has been extracted into the `winenv` crate ready for it. That crate is the
   dependency to take — **not** `pathdoc-core`, which would drag `PathEntry`,
   `Resolved` and `AuditReport` into a tool that has no use for any of them. See
   the crate boundaries below.

   **`winenv` stays in this repository.** Decided, so nobody re-opens it: no
   separate repo, no crates.io. Separate repositories would mean git-revision
   pinning and a cross-repo version bump for every change to a crate that will churn
   while its second consumer is still being written — real cost for a solo
   developer, no offsetting benefit when everything goes public together anyway.
   Publishing would commit to API stability for outside consumers who do not exist.

   The direction, so nothing is designed for the wrong future: **when the env-var
   tool exists, this repository becomes the toolkit workspace and the tools join it
   as members.** Not a third repo, not three repos.

   That cuts against the trunk's one-repository-per-project convention. The
   convention predates a shared-library toolkit being the plan, so the convention
   bends rather than the architecture, and the trunk amends its own steering when the
   restructure actually happens. Do not pre-empt that.
4. **Fix mode.** Only after backup, dry-run and confirmation are designed properly.
   Note the `SetEnvironmentVariable` trap recorded under Verification before
   writing a line of it.
5. **Automated shadowing cross-check** against `Get-Command -All`, as described
   above.

## Shell-level masking

**Status: detection implemented.** PowerShell resolves a bare name as alias, then
function, then cmdlet, then external file — so an alias or function hides an
executable at a layer `PATH` analysis cannot see. On this machine that is 24 names,
including `sc` masking `sc.exe`, the Service Control tool, and `where` masking
`where.exe`.

It extends the per-name records in `executables` rather than becoming a `Finding` or
a section of its own. A `Finding` describes a directory and masking describes none —
the entry holding `sc.exe` is perfectly healthy — and a finding belonging to no index
would break both the type's meaning and the exit-code rule that rests on it.
Splitting it into its own section would be worse: masking is the same question as
shadowing one layer up, and both answer "if I type this, what runs".

### Ask a live shell, and say which shell and whether its profile loaded

The alternative is a static table of known built-ins. That is fast and cannot see a
user's own aliases at all, and it goes stale. Rejected.

Asking a live shell is accurate, shell-specific and slow, and carries a subtlety
that decides the shape of the finding: **`diff` and `fc` are built-in aliases,
present even under `-NoProfile`, while a user's own alias exists only once the
profile loads.** So "was the profile loaded" changes the answer, and both answers
are legitimate for different questions.

That is the same problem as process-only entries, and it gets the same treatment:
report the mechanism and the context, never a bare verdict. The vocabulary already
exists — this is `live_winner` versus `fresh_winner` again, one layer up — and it
should be reused rather than a second one invented. A masking finding therefore
carries which interpreter was asked and whether its profile was loaded, and a
consumer that cares can tell "masked in your interactive shell" from "masked in any
shell".

The interpreter is found in **this tool's own enumeration**, not by a fresh name
lookup. Resolving `powershell` by name would be a second, unaudited `PATH` search
inside a tool whose entire purpose is to distrust `PATH` searches — and on this
machine `pwsh` resolves to a `WindowsApps` reparse point, which this tool flags.
Windows PowerShell is asked rather than `pwsh` for the same reason: it exists on every
Windows machine, whereas `pwsh` is frequently an execution-alias stub that would
launch the Store, which a read-only audit must not do.

`--shell-scan off` skips the scan entirely, and then `Capability::ShellMasking` is
absent so empty `intercepts` read as "not checked" rather than "not masked" — the
same discipline as the shadow capability. An interpreter is left out of
`interpretersConsulted` if it cannot be found, if the spawn fails, or if it exceeds the
timeout. Only interpreters that actually answered are listed, which is precisely what
lets a consumer read an absent record as "clear".

#### What the shell is asked, and what happens when it does not answer

The script is `Get-Alias` plus the `Function:` drive. Deliberately **not**
`Get-Command -CommandType Alias,Function`, which walks every module path to enumerate
commands that autoloading *could* provide: on this machine 1391 constructs against 197,
218 ms against 149 ms, and — the part that decided it — **exactly the same 24 masked
names, with no difference in either direction.** The expensive enumeration bought
nothing.

That distinction was not academic. A GitHub Actions runner exceeded the original
ten-second timeout on every masking test, one of them twice. The timeout is now 30
seconds, but raising it is a **hedge, not a fix** — any fixed value can be exceeded on
a loaded machine — so the script was made cheap at the same time, and that is the
actual remedy.

The 69 ms measured here is the least interesting number in that paragraph. Autoload
discovery scales with the number of **installed modules**, so the local gap describes
this machine's module inventory rather than the operation, and a runner carries far
more. That is almost certainly where the original ten seconds went. The change removed
a cost that grows with the host, which is a different kind of win from a faster
constant, and one no local benchmark can show. Prefer that trade whenever two ways of
asking the same question are otherwise equivalent.

Two things follow about the child process:

- **It is killed on timeout, not abandoned.** The first version handed the whole
  command to a thread and called `output()`, so there was no handle to kill and a
  timed-out shell outlived the audit. That is shipped behaviour rather than a test
  artifact: a long-lived consumer such as the GUI on the roadmap would accumulate one
  orphaned shell per audit. The child is now spawned and held, and killed **and
  reaped** on timeout, on a wait error, and on a pipe-setup failure. Reading still
  happens on a separate thread, because polling for exit without draining the pipe
  would deadlock the child once the buffer filled.
- **Interpreters are deduplicated before anything is spawned**, keyed
  case-insensitively on the resolved absolute path. The first version deduplicated
  against the interpreters that had already *answered*, so a repeated name spawned a
  second time whenever the first attempt failed — two timeouts instead of one.

Masking does **not** gate the exit code. `diff` resolving to `Compare-Object` is
intentional PowerShell design, not a defect, and something is masked on every Windows
machine — so it would be permanently on, which is the argument that removed shadowing
from exit 1 in the first place.

The same rule applies as everywhere else in this spec: **do not bake counts.** How
many names a shell masks is a property of that shell's configuration, not of the
machine.

### Scope, stated rather than left open

| In scope | Out of scope, and why |
| --- | --- |
| PowerShell aliases | `cmd.exe` doskey macros — per-session, not discoverable from outside the session, and nothing on this machine uses them |
| PowerShell functions, which mask a name just as an alias does | Bash and other POSIX shells, until something here actually runs one as a login shell |

Functions are in scope deliberately: leaving them out would report `diff` and miss a
function called `git`, which is the more damaging case.

## Crate boundaries

Three crates, and the boundaries are the point rather than tidiness.

| Crate | Owns | Knows about `PATH`? |
| --- | --- | --- |
| `winenv` | Reading an environment variable from a registry scope, unexpanded, with its value kind. Name enumeration. | No |
| `pathdoc-core` | Splitting, expansion, machine-before-user composition, findings, enumeration, shadowing. | Yes |
| `pathdoc-cli` | Every column width, colour code and exit code. | Yes |

**Dependencies point from each tool at `winenv`, never from one tool at another.**
That is why the registry access is its own crate rather than a public module of
`pathdoc-core`: the env-var backup tool needs registry reads and has no use for
`PathEntry` or `AuditReport`, and a GUI that links several of these tools should not
inherit one tool's model to reach another's plumbing. Normally extracting for a
single consumer would be speculative; there is a known second consumer, which is
exactly when it stops being.

The boundary is drawn at **registry access, not `PATH` semantics**. `winenv` has no
opinion about `;`, about machine-before-user, or about what a directory is.

`winenv` is also deliberately serde-free. `pathdoc-core` owns its wire shape, maps
`winenv::ValueKind` into its own, and rejects anything that is not a string kind —
so adding a kind to `winenv` is a compile error in the adapter rather than a silent
reclassification.

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
