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

Slice 1, part way through. Working today:

- `PATH` read from both registry scopes and composed in the order Windows
  resolves, machine before user
- `REG_SZ` and `REG_EXPAND_SZ` kept apart, with the stored and resolved forms
  both reported
- per-entry findings: missing, not-a-directory, duplicate, empty segment, relative
- directories injected into the live process `PATH` reported as process-only,
  which is legitimate rather than a problem
- table output with colour, and `--json` against a versioned contract

Not built yet: executable enumeration, `PATHEXT` handling, and shadow detection —
which is to say the third and most useful of the three questions above. Until it
lands, the tool says so in as many words rather than reporting zero shadows.

Full behaviour, the JSON contract, verification criteria and roadmap:
[`docs/SPEC.md`](docs/SPEC.md).

## Layout

```
Cargo.toml                      workspace root
crates/pathdoc-core/            library: reads and analyses, returns data, never prints
crates/pathdoc-cli/             binary `pathdoc`: all formatting lives here
docs/SPEC.md                    specification
```

The split is not ceremony. Keeping the core presentation-free is what allows a
shared GUI over several of these tools later, linking the libraries directly
rather than shelling out and scraping text.

## Running it

```powershell
cargo run -p pathdoc-cli --                 # audit this machine
cargo run -p pathdoc-cli -- --json          # the GUI contract
cargo run -p pathdoc-cli -- --scope user    # one registry scope
cargo run -p pathdoc-cli -- --help

cargo test
cargo clippy --all-targets
cargo fmt --check
```

Requires the `stable` toolchain, pinned in `rust-toolchain.toml`. Nothing else.

Run the built binary directly rather than through `cargo run` if the process-only
count matters: cargo prepends its own directories to the child's `PATH`, so
`cargo run` reports four more injected entries than a plain shell does.

Exit codes are `0` clean, `1` findings reported, `2` fatal. The code describes
what was reported, so it respects `--scope`.

## Dependencies

All pinned exactly. Every one of them is here for a stated reason:

| Need | Crate | Why this one |
| --- | --- | --- |
| Registry reads | `winreg` | Every `Reg*` in the `windows` crate is an `unsafe fn`, and `unsafe_code` is `forbid` at workspace level. `winreg` is a thin safe wrapper over `windows-sys`, exposes the value type, and returns values unexpanded. |
| Argument parsing | `clap` (derive) | Also already exits `2` on a usage error, which is the convention here. |
| `--json` | `serde` (optional in core) + `serde_json` | The derives live on the core types so a linked GUI and a JSON consumer see one contract. Optional so a consumer that never serialises does not pay for it. |
| Colour | `anstream` + `anstyle` | Honours `NO_COLOR`, checks for a terminal, and enables Windows virtual terminal processing — the unsafe for which sits in `anstyle-wincon`. Already in the tree via `clap`. |

`unsafe_code` is set to `forbid` at the workspace level, so any crate that needs
unsafe is a dependency rather than something written here.

## Conventions

Line endings are normalised by `.gitattributes`, with test fixtures marked
`binary` so that planned CRLF, lone-CR and NUL-byte cases survive round trips
through git untouched. The machine's global `core.autocrlf=input` cannot affect
them either way.
