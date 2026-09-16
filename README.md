# pathdoc

A read-only auditor for the Windows `PATH`.

It reports which directories are on `PATH` in the order Windows actually resolves
them, which entries are dead or duplicated, and — the useful part — which
executables are shadowing which.

Pointed at a GitHub Actions `windows-latest` runner it finds ten problems in
Microsoft's own image, including five `PATH` directories that do not exist. That is
CI output, not a contrived example: [see below](#what-it-finds-on-somebody-elses-machine).

## Problems this diagnoses

Named concretely, because a symptom is what you search for at the moment you hit it.
Every one of these was hit on a single machine over a single day of provisioning:

- **`git` is not the `git` you installed.** It resolves to a copy vendored inside
  some other application — an Electron app, an AI assistant, an installer's private
  `portable-git` — because that copy's directory sits earlier on `PATH`. There were
  two such copies here, and `gzip`, `bash`, `unzip` and `sdiff` all came from one of
  them.
- **`node`, `npm` or `npx` resolves to the wrong version, or cannot be found at
  all.** Version managers inject a per-shell shim directory, so the answer differs
  between the shell you are in and a shell started fresh, and neither is wrong.
- **`diff`, `fc`, `where`, `sc` and `curl` are not the programs you think they are.**
  In PowerShell they are aliases, resolved *before* `PATH` is searched, so typing
  `sc` never reaches `sc.exe` — the Service Control tool — however healthy that
  directory is. 24 names are masked this way here.
- **A `PATH` entry points at a directory that no longer exists.** Left behind by an
  uninstall, and it slows down every single command lookup.
- **`python` runs a Microsoft Store stub** rather than the interpreter you
  installed, because the stub is a reparse point in `WindowsApps` and nothing said so.
- **A build or a test started failing and nothing in the repository changed**,
  because something rewrote `PATH` underneath it and no shell had been restarted.
- **Two copies of a tool are installed and you cannot tell which one wins** — the
  case that motivated this, where our own `uv` was losing to a vendored copy purely
  on user-`PATH` ordering.

All of it was found by hand. This tool exists so that is one command instead of an
afternoon.

## What it will not do

- **It never writes.** No `PATH` edits, no registry writes, no fix mode, not even
  behind a flag. A tool that audits `PATH` and a tool that edits `PATH` have very
  different blast radii, and the second needs a design for backups, dry-run and
  confirmation before a line of it is written.
- **It never touches the network.** No telemetry, no update check, nothing resolved
  remotely. It reads your registry and the directories already on your `PATH`, and
  that is all.
- **It runs no code of yours unless you ask it to.** The shell scan passes
  `-NoProfile`, so your PowerShell profile is not executed. `--shell-scan profile`
  opts in, and it is the only mode that does.

Stated rather than left to be inferred, because "is it safe to run this on my
machine" should not require reading the source first.

## Install

With Rust already installed:

```powershell
cargo install --git https://github.com/chamal-code/pathdoc pathdoc-cli --locked
```

That builds from source and puts `pathdoc.exe` in `~\.cargo\bin`, which rustup
already has on `PATH`. `--locked` uses the committed `Cargo.lock`, so you get the
dependency versions this was actually tested against. The crates carry
`publish = false` because they are not on crates.io and are not claiming those
names; that does not affect installing from git.

Without Rust, download the zip from the
[latest release](https://github.com/chamal-code/pathdoc/releases/latest), extract it
anywhere, and run `pathdoc.exe`. It is one self-contained executable — no runtime to
install, no installer, and nothing written outside the folder you put it in.

Windows only, and not by omission: it reads the registry and file attributes through
Windows-specific APIs, so the workspace does not compile for any other target.

### The release binary is unsigned

There is no code-signing certificate behind this project, so Windows SmartScreen will
warn the first time you run a downloaded `pathdoc.exe` — usually "Windows protected
your PC", with the real button behind **More info**. That warning is the *absence of a
signature*, not the detection of anything. It cannot be fixed without buying a
certificate, so rather than pretend otherwise: verify the download instead.

Every release ships `SHA256SUMS.txt`:

```powershell
Get-FileHash .\pathdoc-0.1.0-x86_64-pc-windows-msvc.zip -Algorithm SHA256
# then compare Hash against the matching line in SHA256SUMS.txt
```

The zip also contains both licence files and this README, so the licence travels with
the binary as Apache-2.0 requires. If you would rather not trust a prebuilt binary at
all, `cargo install --git` above builds the same commit yourself.

## For automated use

Three facts, if you are wiring this into a script, a CI job, or an agent:

```powershell
pathdoc --json
```

- **`--json` emits a versioned contract.** `schemaVersion` is `4` and is the first
  field. It only increases, and every change so far has been purely additive. Field
  names and enum tags are pinned by tests, so breaking a consumer breaks a build here
  first. Full contract in [`docs/SPEC.md`](docs/SPEC.md).
- **Exit codes are `0` clean, `1` actionable findings reported, `2` fatal.**
  Shadowing and shell masking are always reported and never gate the exit code,
  because something is shadowed and something is masked on every Windows machine, and
  a signal that is on everywhere is not a signal. `--fail-on-shadow` opts in if you
  want it gate-worthy.
- **Check `capabilities` before you trust an empty list.** An empty `executables`
  means "nothing found" only when `shadowDetection` is listed; otherwise it means "not
  computed". The same applies to empty `intercepts` and `shellMasking`. Skip that
  check and you will report a clean bill of health for work that never ran.

Safe to run unattended, per the section above: it never writes and never uses the
network. `--no-color` for clean logs, though `NO_COLOR` is honoured too.

## Status

Slice 1 complete. All three questions above are answered:

- `PATH` read from both registry scopes and composed in the order Windows
  resolves, machine before user
- `REG_SZ` and `REG_EXPAND_SZ` kept apart, with the stored and resolved forms
  both reported
- per-entry findings: missing, not-a-directory, duplicate, empty segment,
  relative, unreadable
- directories injected into the live process `PATH` reported as process-only,
  which is legitimate rather than a problem
- executables enumerated per `PATHEXT`, read from the environment, with every
  name's resolution order reported and contested names flagged — including the
  ones decided by `PATHEXT` rather than `PATH`, which is the case people miss
- reparse points reported rather than followed, so a Store alias stub stays
  distinguishable from a real binary
- shell-level masking: names a PowerShell alias or function answers to before `PATH`
  is searched at all. 24 of them here, including `sc` hiding `sc.exe`, the Service
  Control tool
- table output with colour, and `--json` against a versioned contract

On the machine it was written for that is around a thousand executable names across
23 directories, a few dozen of them resolving from more than one place. Every
finding that took an afternoon to dig out by hand during provisioning is now in the
output, and each one is pinned by a test.

Exact expected numbers live in `crates/pathdoc-core/tests/this_machine.rs` and
nowhere else, deliberately — they moved once already while this README was being
written.

"Which copy wins" is reported for both contexts, because there are two answers.
A per-shell shim injected at the front of the live `PATH` beats a registry entry
now and loses to it after a restart, so the output says which process a verdict
describes, and flags any directory the running process cannot see yet.

Version `0.1.0`, and deliberately not `1.0.0`. The JSON contract is at
`schemaVersion` 4 and the roadmap still holds items that will change it — decoding
`WindowsApps` stubs to their owning package, and an automated cross-check against
`Get-Command`. Semver `0.x` says "this may still change", which is true; `1.0.0`
would promise a stability nobody has decided to offer yet.

The rest of the roadmap is in [`docs/SPEC.md`](docs/SPEC.md), including an env-var
backup and diff tool sharing this registry layer. Mutation stays out until it has a
design for backups, dry-run and confirmation.

Full behaviour, the JSON contract and verification criteria are also in
[`docs/SPEC.md`](docs/SPEC.md).

## Layout

```
Cargo.toml                          workspace root
justfile                            the one entry point: `just check` is the gate
deny.toml                           licence and advisory gates
crates/winenv/                      NOT a pathdoc crate: registry reads, no PATH awareness
crates/pathdoc-core/                library: analyses, returns data, never prints
  src/registry.rs                     thin adapter over winenv
  src/compose.rs                      pure: splitting, expansion, ordering, findings
  src/probe.rs                        the only code touching the disk for entries
  src/executables.rs                  enumeration, PATHEXT, shadow resolution
  tests/this_machine.rs               acceptance test, machine-specific by design
crates/pathdoc-cli/                 binary `pathdoc`: all formatting lives here
  src/options.rs                      clap surface
  src/table.rs                        the human rendering
  src/json.rs                         the versioned contract, with its assertions
docs/SPEC.md                        specification, JSON contract, roadmap
.github/workflows/check.yml         CI: the gate, read-only
.github/workflows/release.yml       tag-triggered release, the only job that can write
.kiro/steering/00-project.md        rules and gotchas for anyone working on this
```

The split is not ceremony.

Keeping the core presentation-free is what allows a shared GUI over several of these
tools later, linking the libraries directly rather than shelling out and scraping
text.

And `winenv` is deliberately outside pathdoc. It answers one question — what is
stored under this name, in this scope, and what kind of value is it — and knows
nothing about `;`, about machine-before-user, or about directories. An env-var
backup tool needs exactly that and none of `PathEntry`, `Resolved` or
`AuditReport`. Dependencies point from each tool at `winenv`, never from one tool at
another.

## Running it from source

If you only want to use the tool, [Install](#install) above is the shorter path. This
section is the contributor's one, from a clone.

```powershell
just                        # list the recipes
just check                  # the full gate for the machine pathdoc describes
just check-portable         # the same gate minus machine-specific tests: use this in CI
just test                   # everything, machine-specific tests included
just test-portable          # only the portable tests, as an outside clone sees them
just test-machine           # only the machine-specific acceptance tests
just audit                  # release build, run without cargo's extra PATH entries
just run --json             # pass flags through to the debug build
```

Or without `just`:

```powershell
cargo run -p pathdoc-cli --                      # audit this machine
cargo run -p pathdoc-cli -- --json               # the GUI contract
cargo run -p pathdoc-cli -- --scope user         # one registry scope
cargo run -p pathdoc-cli -- --fail-on-shadow     # make shadowing gate CI
cargo run -p pathdoc-cli -- --help

cargo test
cargo clippy --all-targets --all-features
cargo clippy -p pathdoc-core --all-targets       # core must be clean without serde too
cargo fmt --check
```

Requires the `stable` toolchain, pinned in `rust-toolchain.toml`. `just`,
`cargo-nextest` and `cargo-deny` for the recipes; plain `cargo` needs nothing extra.

One trap, since it cost two false test failures: `just` on Windows defaults to
running recipes through `sh`, and on this machine the first `sh` on `PATH` is an
MSYS shell vendored inside another application, which prepends `/mingw64/bin` and
`/usr/bin`. The `justfile` pins PowerShell explicitly. Do not remove that line.

Run the built binary directly rather than through `cargo run` if the process-only
count matters: cargo prepends its own directories to the child's `PATH`, so
`cargo run` reports four more injected entries than a plain shell does.

On the exit codes summarised under [For automated use](#for-automated-use), one
detail worth spelling out: the code describes *what was reported*, so it respects
`--scope`. Only per-entry findings gate it — a dead directory, a duplicate, a stray
separator, things a person can go and fix. `system32` alone ships eight names under
two extensions apiece, which is why shadowing does not.

What the output looks like:

```
PATH composition  (10 machine, 18 user, 2 injected at runtime)

  IDX  LIVE  SCOPE         VALUE TYPE     DIRECTORY
    0     1  machine       REG_EXPAND_SZ  C:\WINDOWS\system32
                                          stored as %SystemRoot%\system32
    7     8  machine       REG_EXPAND_SZ  C:\Program Files\Git\cmd
    8     -  machine       REG_EXPAND_SZ  C:\Program Files\GitHub CLI\
   27     -  user          REG_EXPAND_SZ
   28     0  process-only  -              C:\Users\...\fnm_multishells\20244_1789497930171

  7 entries are on PATH in the registry but not in this process. Restart the
  shell to pick them up.

Findings  (2)

   27  empty segment
   29  missing        C:\Users\...\AppData\Local\Programs\Ollama

Shadowed executables  (48 of 1039 names)

  git
    wins    #7   C:\Program Files\Git\cmd\git.exe
    hidden  #16  C:\Users\...\hermes\git\cmd\git.exe
    hidden  #17  C:\Users\...\hermes\git\bin\git.exe
  corepack
    wins    #28  C:\Users\...\fnm_multishells\20244_1789497930171\corepack.cmd
    unseen  #23  C:\Users\...\fnm\aliases\default\corepack.cmd
    note    a new process would run C:\Users\...\fnm\aliases\default\corepack.cmd
  sc
    intercept  alias -> Set-Content
    wins    #0   C:\WINDOWS\system32\sc.exe
  winrm  one directory, decided by PATHEXT order
    wins    #0   C:\WINDOWS\system32\winrm.cmd
    hidden  #0   C:\WINDOWS\system32\winrm.vbs
```

`intercept` is the shell layer: PowerShell resolves alias, then function, then cmdlet,
then external file, so typing `sc` never reaches `sc.exe` — the Service Control tool —
however healthy that directory is. It is **shell-layer only**: anything spawning a
process by `PATH` search still gets the file.

The verdict depends on which shell you ask, so `--shell` takes one or more and the
report lists every interpreter it consulted. On this machine:

```powershell
pathdoc --shell powershell --shell pwsh
```

| Name | Windows PowerShell 5.1 | PowerShell 7 |
| --- | --- | --- |
| `curl` | alias for `Invoke-WebRequest` | clear, runs `curl.exe` |
| `sc` | alias for `Set-Content` | clear, runs `sc.exe` |
| `where`, `fc`, `ls` | masked | masked |

Because both shells appear in `interpretersConsulted`, a name with no record for one
of them was **asked and is clear** — not simply unexamined. That distinction is why
`intercepts` is a list and why the consulted set is reported at all.

Masking never affects the exit code. `diff` resolving to `Compare-Object` is
intentional design, and something is masked on every Windows machine.
`--shell-scan off` skips the scan; `--shell-scan profile` also loads your profile,
which is the only way to see your own aliases and means this tool executes your
profile code, so it is opt-in.

`LIVE` is the position in the current process's `PATH`; `-` means the running
process cannot see that directory at all. `IDX` is the composed registry position,
which is what a newly started process resolves by. The `corepack` block is what it
looks like when those two disagree.

## Dependencies

All pinned exactly. Every one of them is here for a stated reason:

| Need | Crate | Why this one |
| --- | --- | --- |
| Registry reads | `winreg`, via `winenv` | Every `Reg*` in the `windows` crate is an `unsafe fn`, and `unsafe_code` is `forbid` at workspace level. `winreg` is a thin safe wrapper over `windows-sys`, exposes the value type, and returns values unexpanded. Only `winenv` depends on it. |
| Argument parsing | `clap` (derive) | Also already exits `2` on a usage error, which is the convention here. |
| `--json` | `serde` (optional in core) + `serde_json` | The derives live on the core types so a linked GUI and a JSON consumer see one contract. Optional so a consumer that never serialises does not pay for it. |
| Colour | `anstream` + `anstyle` | Honours `NO_COLOR`, checks for a terminal, and enables Windows virtual terminal processing — the unsafe for which sits in `anstyle-wincon`. Already in the tree via `clap`. |

`unsafe_code` is set to `forbid` at the workspace level, so any crate that needs
unsafe is a dependency rather than something written here.

## Conventions

Line endings are normalised by `.gitattributes`. The machine's global
`core.autocrlf=input` cannot affect this repository either way.

Fixture directories are marked `binary` in the same file so that a fixture
containing CRLF, a lone CR, or NUL bytes would survive git untouched. No fixture
directory exists yet — slice 1 did not need one, since the tests either supply
inputs inline or create real files in a temp directory they clean up. The rule
stays because a normalised fixture is a silently meaningless test.

## Testing

174 tests, in three groups:

- **Unit tests**, portable. Every input is explicit, including the environment
  lookup, so no machine's layout leaks into the logic. None of them asks an external
  process what the machine is configured like — the shell scan runs against an
  injected fake, which also makes spawn counts assertable. A few do spawn `cmd.exe`
  or `icacls` where the process behaviour is itself the subject and the assertion is
  a marker file or an ACL rather than a duration.
- **Contract tests** in `json.rs`, pinning every JSON field name and enum tag, so
  breaking the contract a GUI depends on breaks a test.
- **`tests/this_machine.rs`**, 24 acceptance tests. Deliberately machine-specific:
  they describe the registry of the machine this was written on. Composition order is
  cross-checked at run time against
  `[Environment]::GetEnvironmentVariable('Path', ...)` rather than hard-coded.
  Volatile counts sit in one marked block at the top; everything else is keyed on
  directory names so installing something does not invalidate them.

### If you have cloned this, 24 tests will skip, and that is correct

```
cargo test
...
test result: ok. 0 passed; 0 failed; 24 ignored
```

Those are the machine-specific ones. They carry `#[ignore]` precisely so that a
fresh clone passes: their assertions are about one machine's `PATH`, and yours is
different. Nothing is wrong, and there is nothing to fix.

On the machine they describe they still run on every commit, because `just test`
passes `--run-ignored all`. That combination is deliberate — excluding them outright
would have been simpler and would have thrown away a drift canary that has caught
two unannounced `PATH` changes. `just test-portable` shows exactly what you see;
`just test-machine` runs only them.

## CI and releases

`.github/workflows/check.yml`, two jobs, and the split is forced by the code rather
than chosen:

- **windows-latest** runs `just check-portable` — formatting, clippy in both feature
  configurations, the portable tests, and the licence and advisory gates. It then
  builds the release binary and audits the runner's own `PATH`, which is the only way
  to prove the tool works on a machine it was not written on. `pathdoc` exiting 1
  there is a pass: it means findings were reported.
- **ubuntu-latest** runs only `just fmt-check` and `just deny`.

Linux is limited to those two because **this workspace cannot be built for Linux at
all**: `pathdoc-core` reads file attributes through
`std::os::windows::fs::MetadataExt` so a reparse point is reported rather than
followed, and `winenv` depends on `winreg`. A Linux build job would fail for a reason
that has nothing to do with the code being wrong.

That job still earns its place. It is the only thing that exercises
`set windows-shell` in the justfile — with `set shell` those two recipes would try to
spawn `powershell.exe` on Ubuntu. And `cargo deny` resolves the graph for the target
named in `deny.toml`, so the licence verdict is host-independent.

### What it finds on somebody else's machine

The Windows job audits the runner's own `PATH`, which makes every CI run a test of
whether this tool generalises past the machine it was written on. On a
`windows-latest` runner:

```
PATH composition  (68 machine, 4 user, 0 injected at runtime)
Findings  (10)
schemaVersion 3, 72 entries, 1537 names
```

Ten findings on Microsoft's own runner image, including **five directories on `PATH`
that do not exist** and a `dotnet\` entry duplicating an earlier one. Across 72
entries and 1537 executable names, none of which anybody here chose.

That is better evidence than any example this README could construct, and it is
reproducible: the workflow is in this repository, so the numbers above come from a
machine neither the author nor you controls. It also means the tool is not
pattern-matching one hand-tuned `PATH` — the assertions in `this_machine.rs` describe
one machine, but the analysis does not.

### And it found a real bug on its third run

The shell scan measures at about 150 ms here. On the runner it exceeded a ten-second
timeout on every masking test, which surfaced three defects that no amount of local
measurement would have:

- the timed-out shell was **abandoned rather than killed**, because the original code
  handed the whole `Command` to a thread and called `output()`, leaving no handle. That
  ships: a long-running consumer would leak one shell per audit. `cargo nextest`
  reported it as `LEAK` on a test that *passed*
- three portable tests asserted a live interpreter answers, so a slow machine failed
  them. They now run against an injected fake, and the one real-shell test lives in
  `this_machine.rs` and skips loudly
- interpreters were deduplicated against the ones that had already *answered*, so a
  repeated name spawned twice when the first attempt failed. One test took 20 seconds
  where the others took 10

The remedy was to make the script cheap rather than to raise the limit — `Get-Alias`
plus the `Function:` drive instead of `Get-Command -CommandType Alias,Function`, which
walks every module path for autoload discovery. 197 constructs against 1391, and
identical results. The timeout went up as well, to 30 seconds, but that is a hedge.

The local benchmark said 149 ms against 218 ms, and it understated the fix. Autoload
discovery scales with the number of installed modules, so that 69 ms is a fact about
one machine's module inventory rather than about the operation — and a runner carries
far more modules than this machine does. The point was never trimming 69 ms; it was
deleting a cost that grows with the host, which no local measurement can show you.
The run after the fix: zero `LEAK` markers, 150 passed and 24 skipped in 5.6 s, and
no test over ten seconds.

### Releases

`.github/workflows/release.yml`, triggered by pushing a tag matching `v*`. Two jobs,
and here the split is about privilege:

- **`gate`** runs `just check-portable` and holds `contents: read`. It also checks the
  tag against the version in `Cargo.toml`, so a mistagged release cannot ship a binary
  whose `--version` contradicts its own filename.
- **`release`** builds with `--locked`, packages, and publishes. It is the only job in
  this repository holding `contents: write`, and `needs: gate` means an artifact
  nobody has tested cannot be published.

Least privilege is per job rather than per repository, and the privileged job
deliberately runs **no third-party action**. The gate needs `just`, `nextest` and
`deny`, so it uses `taiki-e/install-action` with a token that can only read a public
repo. The release job uses first-party checkout, the toolchain already on the runner,
and `gh`, which is preinstalled. So the token that can write here is never in a job
executing somebody else's code.

Values from the event reach PowerShell through `env:` rather than `${{ }}`
interpolation into the script body, because `${{ }}` is textual substitution and a ref
containing a quote would be splicing itself into a script.

The artifact is a zip, not a bare `.exe`: `pathdoc.exe`, `LICENSE-APACHE`,
`LICENSE-MIT` and `README.md`, alongside a separate `SHA256SUMS.txt`. Apache-2.0
section 4 requires the licence to travel with a redistribution, and a lone executable
does not carry it — the same class of gap as declaring a licence in `Cargo.toml` with
no files behind it, which this repository also had until it was caught.

## Licence

Dual licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. This is the usual Rust convention, and it is what
`license = "MIT OR Apache-2.0"` in the workspace manifest has been claiming since
the first commit — the files themselves only arrived when the repository was
prepared for publication, which is worth knowing if you are auditing history.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this work by you shall be dual licensed as above, without any
additional terms or conditions.
