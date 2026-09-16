# One agreed entry point for both agent sessions and a human.
#
# `project.manifest.json` points at these recipes, which makes its commands block
# executable truth rather than documentation that drifts.
#
# Note: `just` itself may not resolve yet if it was installed after your shell
# started. That is not a broken install — restart the shell, or invoke it by full
# path once. pathdoc's LIVE column shows exactly which entries are in that state.

# Recipes run in PowerShell, explicitly, and this matters more than it looks.
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
set shell := ["powershell.exe", "-NoProfile", "-Command"]

default:
    @just --list

# Everything CI would run, in the order that fails fastest.
check: fmt-check lint test deny

# Run the whole test suite.
test:
    cargo nextest run --all-features

# Run only the machine-specific acceptance test, with output shown.
test-machine:
    # When this fails the machine changed. Ask the trunk what it did before
    # touching a number in it.
    cargo nextest run -p pathdoc-core --test this_machine --no-capture

# Clippy over everything, in both feature configurations.
lint:
    cargo clippy --all-targets --all-features
    # pathdoc-core must also stay clean without serde: a GUI linking the library
    # directly may not want it, and that configuration is not otherwise built.
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

# Audit this machine with the release build, without cargo's extra PATH entries.
audit:
    # `cargo run` prepends four directories to the child's PATH, which inflates the
    # process-only count. Invoking the binary directly does not.
    cargo build --release -p pathdoc-cli
    ./target/release/pathdoc.exe

# Print the PATH a recipe actually sees. Kept because the answer was a surprise once.
probe-path:
    cargo run -q -p pathdoc-cli -- --no-color --scope machine
