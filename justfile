# One agreed entry point for both agent sessions and a human.
#
# `project.manifest.json` points at these recipes, which makes its commands block
# executable truth rather than documentation that drifts.
#
# Note: `just` itself may not resolve yet if it was installed after your shell
# started. That is not a broken install — restart the shell, or invoke it by full
# path once. pathdoc's LIVE column shows exactly which entries are in that state.
#
# Comments explaining a recipe go ABOVE it, not inside it: `just` echoes each line
# of a recipe body, so an in-body comment gets printed as if it were output.

# Recipes run in PowerShell on Windows, explicitly, and this matters more than it
# looks.
#
# `just` on Windows defaults to running recipes through `sh`, and the `sh` it finds
# here is the MSYS shell vendored inside hermes' git. That shell prepends
# `/mingw64/bin` and `/usr/bin` to PATH, so a recipe saw a different PATH from the
# shell that invoked it — with a second `git.exe` and `bash.exe` ahead of the real
# ones. It broke two acceptance assertions and it would have quietly falsified any
# audit run through `just`.
#
# `-NoProfile` because the invoking shell's PATH is inherited anyway, including
# fnm's activation; re-running the profile would only add cost and variance.
#
# `windows-shell` and not `shell`: `shell` overrides every platform, and the reason
# above is Windows-specific. `fmt-check` and `deny` are platform-independent, so a
# Linux runner in a future OS matrix would otherwise try to spawn powershell.exe.
set windows-shell := ["powershell.exe", "-NoProfile", "-Command"]

default:
    @just --list

# Everything CI would run, in the order that fails fastest.
check: fmt-check lint test deny

# Run the whole test suite.
test:
    cargo nextest run --all-features

# When this fails the machine changed. Ask the trunk what it did before touching a
# number in it.

# Run only the machine-specific acceptance test, with output shown.
test-machine:
    cargo nextest run -p pathdoc-core --test this_machine --no-capture

# The second run is not redundant: `pathdoc-core` must stay clean without `serde`
# too, because a GUI linking the library directly may not want it, and no other
# command builds that configuration.

# Clippy over everything, in both feature configurations.
lint:
    cargo clippy --all-targets --all-features
    cargo clippy -p pathdoc-core --all-targets

# Apply formatting.
fmt:
    cargo fmt --all

# Check formatting without changing anything.
fmt-check:
    cargo fmt --all --check

# Licence and advisory gates, configured in deny.toml.
deny:
    cargo deny check

# Audit this machine with the debug build. Pass flags through, e.g. `just run --json`.
run *ARGS:
    cargo run -p pathdoc-cli -- {{ARGS}}

# `cargo run` prepends four directories to the child's PATH, which inflates the
# process-only count. Invoking the built binary directly does not.

# Audit this machine with the release build, without cargo's extra PATH entries.
audit:
    cargo build --release -p pathdoc-cli
    ./target/release/pathdoc.exe

# Deliberately not `pathdoc`, which reads the registry: shell injection exists only
# in this recipe's own process block, so only the process block can reveal it. This
# is how the vendored-`sh` problem was found.

# Print the PATH a recipe actually sees.
probe-path:
    @$i = 0; ($env:PATH -split ';') | ForEach-Object { "{0,3} [{1}]" -f $i, $_; $i++ }
