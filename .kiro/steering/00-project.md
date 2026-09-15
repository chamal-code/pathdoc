# pathdoc — project steering

Project-specific rules. Global steering in `~/.kiro/steering/` is inherited; do
not duplicate it here.

## The two rules that matter

**1. The core crate never prints.** `pathdoc-core` returns data structures.
Every `println!`, colour code and column width belongs to `pathdoc-cli`. This is
what keeps a future shared GUI able to link the library directly instead of
shelling out and parsing text. If a function in core needs to format something
for display, it is in the wrong crate.

**2. Slice 1 is read-only.** No registry writes, no PATH edits, no fix mode,
not even behind a flag. A tool that audits PATH and a tool that edits PATH have
very different blast radii, and the second one needs a design for backups,
dry-run and confirmation before any code is written. Do not let it creep in.

## Verification is concrete here

The expected findings on this machine were established by hand during
provisioning on 2026-09-15 and are written into `docs/SPEC.md` under
Verification. Treat that list as the acceptance test: one dead `Ollama` entry,
three `git.exe` with `Program Files` winning, vendored `gzip`/`bash`/`unzip`/`sdiff`,
`python` from `~\.local\bin` with no `WindowsApps` stub, `uv` twice with
`WinGet\Links` winning, and the `fnm_multishells` entry **not** flagged.

Cross-check against `Get-Command <name> -All`, which is the independent
reference. Remember it also returns aliases and functions: `diff` and `fc` are
PowerShell aliases on this machine, not programs, and shell-level masking is
explicitly a later slice.

## Gotchas already known

- Compose PATH as **machine first, then user**. Getting this backwards inverts
  every shadowing verdict.
- Read `PATHEXT` from the environment; do not hard-code the list.
- Distinguish `REG_SZ` from `REG_EXPAND_SZ`. A literal `%USERPROFILE%` and an
  expanded one are different facts.
- Process-only entries are normal, not errors. `fnm` injects a per-shell shim
  directory on activation.
- Report reparse points rather than following them, so Store alias stubs stay
  identifiable.

## Test fixtures

`.gitattributes` marks fixture directories `binary`. Planned cases include CRLF,
lone CR and NUL bytes; if git ever normalises those the tests become nonsense.
Do not relax that rule.
