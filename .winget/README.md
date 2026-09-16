# winget manifests

The `winget` package manifests for `pathdoc`, kept here so the next release is an edit
rather than a rediscovery. This directory is **not** consumed by anything: winget reads
its manifests from Microsoft's [winget-pkgs](https://github.com/microsoft/winget-pkgs)
repository, and these files are the copy that gets submitted there.

Deliberately not wired into any workflow. Automating a submission that has not been
made by hand once is premature, and the first one is where the fields get understood.

## Current state: 0.1.1, complete and validated, not yet submitted

`winget validate` passes. All seven URLs answer 200, `InstallerSha256` matches the
published artifact, and `RelativeFilePath` matches what is actually inside it. Nothing
has gone to winget-pkgs yet; opening that PR is the owner's call.

**`0.1.0` was prepared and then held**, which is why the first submitted version is
`0.1.1`. `--help` printed four em dashes as mojibake on a non-UTF-8 console. Ordinarily
that would ride to the next release, but a winget manifest pins an artifact URL *and its
hash*, so submitting it would have meant a `0.1.1` release plus a second PR to a
Microsoft repository to undo. Fixing first cost four characters. **Check the emitted
output of the binary before pinning it here** — a manifest is a commitment to a specific
file, so the bar is higher than for a normal release.

While the release did not yet exist, `ReleaseDate` and `InstallerSha256` were held as
placeholders that **deliberately failed `winget validate`**. Do the same next time.
Carrying the previous version's real values forward would have been strictly worse: the
manifest would have validated cleanly while pointing at the wrong artifact. A value that
cannot validate is a tripwire; a stale-but-plausible value is a footgun. `winget
validate` names both fields, so neither can be quietly forgotten.

## Layout

`manifests/c/chamal-code/pathdoc/0.1.1/` mirrors the path these files occupy in
winget-pkgs exactly, so a submission is a copy rather than a reconstruction. That path
is not arbitrary: the first directory is the first letter of the identifier lowercased,
then one directory per period-separated segment of the identifier — case sensitive —
then the version.

```
manifests/c/chamal-code/pathdoc/0.1.1/
  chamal-code.pathdoc.yaml                 version manifest
  chamal-code.pathdoc.installer.yaml       installer manifest
  chamal-code.pathdoc.locale.en-US.yaml    defaultLocale manifest
```

Schema `1.12.0` for all three. The identifier is `chamal-code.pathdoc`, mirroring the
GitHub path rather than the licence or the publisher name.

The manifests carry no comments beyond the schema line, on purpose. They are meant to
be copied into a Microsoft repository verbatim, and a reviewer there should see
idiomatic manifests rather than our reasoning. The reasoning lives in this file.

## Per-release checklist

Every one of these carries the version. Eight lines across the three files, plus the
directory name and the release date — which is why this list exists rather than a
vague "update the version".

1. **Rename the version directory**, `0.1.1` to the new one.
2. **`PackageVersion`** in all three files.
3. **`InstallerUrl`** in the installer manifest. It carries the version *twice*, once
   as the tag (`v0.1.1`) and once in the asset filename (`0.1.1`).
4. **`InstallerSha256`**, copied from the release's published `SHA256SUMS.txt`. See
   below.
5. **`RelativeFilePath`**, which embeds the version because the zip's top-level
   directory does. The easiest one to forget, and it fails at install time rather than
   at validation.
6. **`ReleaseDate`** in the installer manifest, as the UTC date of publication. The
   release API reports `published_at` in UTC; converting it to local time can move it
   a day.
7. **The three tagged URLs** in the defaultLocale manifest: `LicenseUrl`,
   `ReleaseNotesUrl` and the `Documentations` entry all point at `v0.1.1`. Leaving
   these behind is silent — the links resolve, they just describe the wrong version.

Find every occurrence before editing, substituting the version you are moving *from*:

```powershell
Select-String -Path .\manifests\c\chamal-code\pathdoc\*\*.yaml -Pattern '0\.1\.1'
```

Afterwards, run it again for the old version and expect zero hits. That is the check
that catches items 5 and 7, the two that fail quietly.

Then validate, from the repository root:

```powershell
winget validate --manifest .\.winget\manifests\c\chamal-code\pathdoc\0.1.1\
```

`winget validate` checks the manifests against the schema. It does **not** check that
the URLs resolve or that `RelativeFilePath` matches what is actually inside the
archive, so check those too:

```powershell
# every URL should answer 200
Select-String -Path .\manifests\c\chamal-code\pathdoc\0.1.1\*.yaml -Pattern 'https://\S+' -AllMatches |
    ForEach-Object { $_.Matches.Value } |
    Where-Object { $_ -notlike '*aka.ms*' } | Sort-Object -Unique |
    ForEach-Object { "$((Invoke-WebRequest $_ -Method Head -UseBasicParsing).StatusCode)  $_" }

# the archive really contains the nested path the manifest names
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::OpenRead($zipPath).Entries | ForEach-Object { $_.FullName }
```

## Decisions worth not relitigating

**`InstallerType: zip` with `NestedInstallerType: portable`.** The release asset is an
archive rather than an installer, and the executable sits inside a version-named
top-level directory. That directory is deliberate — it stops an extraction from
scattering four loose files across a Downloads folder — and the cost is that
`RelativeFilePath` has to name it, version included.

**The checksum is copied, never recomputed.** It comes from the `SHA256SUMS.txt`
published with the release. Recomputing it locally would make the manifest agree with
whatever is on this disk, which is the opposite of the point: the value exists so a
user can tell that what they downloaded is what was published. If a locally computed
hash ever disagrees with the published file, that is a finding about the release, not a
typo to correct here.

**`LicenseUrl` points at the README's licence section at the tag**, not at a licence
file and not at a branch. At the tag because a licence can change over time and the
link should describe this version; at the README section because the package is dual
licensed `MIT OR Apache-2.0`, and that section states the choice and links both files,
which neither licence file can do alone.

**`Moniker: pathdoc`** is what makes `winget install pathdoc` work instead of requiring
the full `chamal-code.pathdoc`. Omitting it is a silent loss of usability.

**Tags are symptom words, not abstractions.** `dead-path-entries` and `shadowing` are
what somebody types when they have the problem; "utility" is not. Lowercase with
hyphens per the schema's stated best practice, and the cap is 16 — currently 15, so
there is one spare.

## Deliberately absent

- **`Description`** — the schema says winget does not currently use it, so a second
  longer description would be dead weight.
- **`Agreements`** — only permitted for verified developers.
- **`Icons`** — the field *does* exist in the 1.12.0 defaultLocale schema, which is
  worth knowing because it is easy to assume otherwise. It is left out because winget
  serves its own package icons from a Microsoft-internal repository through the client,
  so an icon here would buy nothing.
- **Anything matching Add/Remove Programs.** The schema's guidance about aligning
  `Publisher`, `PackageName` and `PackageVersion` with ARP registry entries is aimed at
  MSI and EXE installers. A portable package creates no ARP entry, so the plain semver
  and the plain names are correct and `AppsAndFeaturesEntries` is not needed.

## What installation actually does

For a nested portable, winget extracts the archive and creates a shim named by
`PortableCommandAlias`. The binary is never executed during installation, so
`pathdoc`'s exit codes — `1` means findings were reported — cannot affect validation.
