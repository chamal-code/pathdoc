<!--
Body of every GitHub release, filled in by .github/workflows/release.yml.

A separate file rather than a here-string inside the workflow, for a reason worth
recording: a PowerShell here-string terminator must be the first thing on its line,
while a YAML block scalar requires every content line to be indented past its key.
Those two rules cannot both be satisfied, so embedding release notes in `run: |`
silently truncates the block and produces invalid YAML. Keeping the notes here also
means they can be edited and reviewed without touching a workflow.

Placeholders, all three substituted by the workflow, which fails if any survives:

  {{REPO}}  owner/name, e.g. chamal-code/pathdoc
  {{TAG}}   the tag as pushed, e.g. v0.1.0
  {{STEM}}  the asset basename, e.g. pathdoc-0.1.0-x86_64-pc-windows-msvc

This comment is HTML, so GitHub does not render it.
-->
A read-only auditor for the Windows `PATH`. It reports which directories are on `PATH`
in the order Windows actually resolves them, which entries are dead or duplicated, and
which executables are shadowing which.

**It never writes, and it never touches the network.**

## Install

With Rust:

```
cargo install --git https://github.com/{{REPO}} pathdoc-cli --locked
```

Or download `{{STEM}}.zip` below, extract it, and run `pathdoc.exe`. It is
self-contained: no runtime to install and no installer. Windows x64 only, because it
reads the registry and file attributes through Windows APIs and does not compile for
other targets.

## Verify the download

The binary is **unsigned**, so SmartScreen will warn the first time you run it, usually
"Windows protected your PC" with the real button behind **More info**. That is the
absence of a signature rather than the detection of anything, and it cannot be fixed
without a code-signing certificate.

```powershell
Get-FileHash .\{{STEM}}.zip -Algorithm SHA256
```

Compare the result against `SHA256SUMS.txt` below. The zip also carries both licence
files and the README, so the licence travels with the binary as Apache-2.0 requires.

## For automated use

`--json` emits a versioned contract, currently `schemaVersion` 4. Exit codes are `0`
clean, `1` actionable findings reported, `2` fatal. Shadowing and shell masking are
always reported and never gate the exit code. Read `capabilities` before treating an
empty list as "nothing found" rather than "not computed".

- [README](https://github.com/{{REPO}}/blob/{{TAG}}/README.md)
- [Contract and roadmap](https://github.com/{{REPO}}/blob/{{TAG}}/docs/SPEC.md)

Version `0.x` deliberately: roadmap items that would change the JSON contract are
still outstanding, so `0.x` is the accurate claim and `1.0.0` would promise a
stability nobody has decided to offer.
