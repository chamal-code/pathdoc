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

Skeleton. The data model in `pathdoc-core` is settled and the specification is
written; the logic is not implemented yet. `cargo build` and `cargo test` pass
from the first commit so there is a green baseline to work against.

Full behaviour, verification criteria and roadmap: [`docs/SPEC.md`](docs/SPEC.md).

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
cargo run -p pathdoc-cli --
cargo test
cargo clippy --all-targets
cargo fmt --check
```

Requires the `stable` toolchain, pinned in `rust-toolchain.toml`. Nothing else.

## Likely dependencies

Not yet added — these are implementation decisions for whoever picks up the
first task, listed so the choice is deliberate rather than accidental:

| Need | Candidate |
| --- | --- |
| Registry reads | `winreg`, or `windows` for a fuller API surface |
| Argument parsing | `clap` with derive |
| `--json` output | `serde` + `serde_json` |

`unsafe_code` is set to `forbid` at the workspace level, so any crate that needs
unsafe should be a dependency rather than something written here.

## Conventions

Line endings are normalised by `.gitattributes`, with test fixtures marked
`binary` so that planned CRLF, lone-CR and NUL-byte cases survive round trips
through git untouched. The machine's global `core.autocrlf=input` cannot affect
them either way.
