# pathdoc

A read-only auditor for the Windows `PATH`.

It reports which directories are on `PATH` in the order Windows actually resolves
them, which entries are dead or duplicated, and — the useful part — which
executables are shadowing which.

**It never writes.** No PATH edits, no registry writes, no fix mode. That is a
deliberate constraint, not an unfinished feature.

## Why

Provisioning this machine turned up `git` resolving into a retired application's
private folder, a second vendored `git` hiding somewhere else, `gzip`, `bash`,
`unzip` and `sdiff` all coming from that same folder, `python` resolving to a
Microsoft Store stub, our own `uv` losing to a vendored copy on user-PATH order,
and one entry pointing at a directory that no longer exists. All of it found by
hand. This tool exists so that is a command instead of an afternoon.

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

Next up is the roadmap in [`docs/SPEC.md`](docs/SPEC.md) — shell-level alias
masking, decoding `WindowsApps` stubs to their owning package, and an env-var
backup and diff tool sharing this registry layer. Mutation stays out until it has
a design for backups, dry-run and confirmation.

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

## Running it

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

Exit codes are `0` clean, `1` actionable findings reported, `2` fatal. The code
describes what was reported, so it respects `--scope`.

Only per-entry findings gate it — a dead directory, a duplicate, a stray separator,
things a person can go and fix. Shadowing is always reported but never fails the
run, because `system32` alone ships eight names under two extensions apiece and a
signal that is on for every machine is not a signal. Use `--fail-on-shadow` when
you do want it gate-worthy.

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
  winrm  one directory, decided by PATHEXT order
    wins    #0   C:\WINDOWS\system32\winrm.cmd
    hidden  #0   C:\WINDOWS\system32\winrm.vbs
```

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

136 tests, in three groups:

- **Unit tests**, portable. Every input is explicit, including the environment
  lookup, so no machine's layout leaks into the logic.
- **Contract tests** in `json.rs`, pinning every JSON field name and enum tag, so
  breaking the contract a GUI depends on breaks a test.
- **`tests/this_machine.rs`**, 19 acceptance tests. Deliberately machine-specific:
  they describe the registry of the machine this was written on. Composition order is
  cross-checked at run time against
  `[Environment]::GetEnvironmentVariable('Path', ...)` rather than hard-coded.
  Volatile counts sit in one marked block at the top; everything else is keyed on
  directory names so installing something does not invalidate them.

### If you have cloned this, 19 tests will skip, and that is correct

```
cargo test
...
test result: ok. 0 passed; 0 failed; 19 ignored
```

Those are the machine-specific ones. They carry `#[ignore]` precisely so that a
fresh clone passes: their assertions are about one machine's `PATH`, and yours is
different. Nothing is wrong, and there is nothing to fix.

On the machine they describe they still run on every commit, because `just test`
passes `--run-ignored all`. That combination is deliberate — excluding them outright
would have been simpler and would have thrown away a drift canary that has caught
two unannounced `PATH` changes. `just test-portable` shows exactly what you see;
`just test-machine` runs only them.

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
