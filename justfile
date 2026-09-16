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

# The full gate for THIS machine. Includes the machine-specific acceptance tests, so
# it fails anywhere else by design — see `check-portable` for CI.

# Everything, in the order that fails fastest. Use on the machine pathdoc describes.
check: fmt-check lint test deny

# What CI should run, and the only gate that is safe off this machine. Same checks,
# minus the acceptance tests that describe one particular registry.

# The portable gate: no machine-specific tests.
check-portable: fmt-check lint test-portable deny

# `--run-ignored all` is what keeps the machine-specific acceptance tests inside the
# gate. They carry `#[ignore]` so that a plain `cargo test` on somebody else's clone
# passes and skips them, but on this machine they are exactly the tests worth running
# on every commit — they have caught two unannounced PATH changes.

# Run the whole test suite, machine-specific tests included.
test:
    cargo nextest run --all-features --run-ignored all

# What a stranger's fresh clone sees: no machine-specific tests, no skips to explain.
# Useful for checking the public experience without leaving this machine.

# Run only the portable tests, as an outside contributor would.
test-portable:
    cargo nextest run --all-features

# When this fails the machine changed. Ask the trunk what it did before touching a
# number in it.

# Run only the machine-specific acceptance tests, with output shown.
test-machine:
    cargo nextest run -p pathdoc-core --test this_machine --run-ignored all --no-capture

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
