//! Command-line front end for `pathdoc-core`.
//!
//! All formatting lives here. The core crate returns data and never prints.
//!
//! Exit codes, matching the convention used across this machine's tooling:
//! `0` nothing to report, `1` findings present, `2` fatal error.

use std::process::ExitCode;

/// Exit code for a clean audit.
const EXIT_CLEAN: u8 = 0;
/// Exit code when the audit found something worth reporting.
const EXIT_FINDINGS: u8 = 1;
/// Exit code for a fatal error.
const EXIT_FATAL: u8 = 2;

fn main() -> ExitCode {
    match pathdoc_core::audit() {
        Ok(report) => {
            // Skeleton output. Real table and --json rendering are the second
            // task in the project window; see docs/SPEC.md.
            println!("pathdoc: {} PATH entries examined", report.entries.len());
            println!("pathdoc: {} shadowed executables", report.shadows.len());

            if report.has_findings() {
                ExitCode::from(EXIT_FINDINGS)
            } else {
                ExitCode::from(EXIT_CLEAN)
            }
        }
        Err(err) => {
            eprintln!("pathdoc: {err}");
            ExitCode::from(EXIT_FATAL)
        }
    }
}
