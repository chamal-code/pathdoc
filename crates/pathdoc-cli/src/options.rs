//! Command-line surface, as specified in `docs/SPEC.md`.

use clap::{Parser, ValueEnum};
use pathdoc_core::{PathEntry, PathScope};

/// Read-only auditor for the Windows `PATH`.
#[derive(Debug, Parser)]
#[command(
    name = "pathdoc",
    version,
    about = "Audit the Windows PATH: composition order, dead entries, shadowed executables.",
    long_about = "Audit the Windows PATH.\n\n\
                  Reads the stored value from HKLM and HKCU and composes it the way Windows \
                  resolves it, machine entries before user entries, then reports what is wrong \
                  with each one. Directories injected into the live process PATH but present in \
                  neither registry scope are reported as process-only, which is legitimate \
                  rather than a problem.\n\n\
                  It never writes. No PATH edits, no registry writes, no fix mode.\n\n\
                  Exit codes: 0 nothing to report, 1 findings present, 2 fatal error. The exit \
                  code describes what was reported, so it respects --scope."
)]
pub struct Options {
    /// Emit the report as JSON instead of a table.
    ///
    /// A versioned, documented shape — see the JSON contract in `docs/SPEC.md`.
    #[arg(long)]
    pub json: bool,

    /// Which scopes to report on. Composition and indices are unaffected.
    #[arg(long, value_enum, default_value_t = ScopeFilter::All)]
    pub scope: ScopeFilter,

    /// Report only shadowed executables, omitting the composition table.
    #[arg(long)]
    pub shadows_only: bool,

    /// Never emit colour, whatever the destination supports.
    #[arg(long)]
    pub no_color: bool,
}

impl Options {
    /// Whether an entry survives the `--scope` filter.
    pub fn includes(&self, entry: &PathEntry) -> bool {
        match self.scope {
            ScopeFilter::All => true,
            ScopeFilter::Machine => entry.scope == PathScope::Machine,
            ScopeFilter::User => entry.scope == PathScope::User,
        }
    }
}

/// Which `PATH` scopes to report on.
///
/// A display filter only. Entries keep the index they hold in the full composed
/// order, so a filtered report still says where each entry really sits — which
/// is the whole point of composing machine before user in the first place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ScopeFilter {
    /// Everything, including directories injected at runtime.
    All,
    /// Only `HKLM` entries.
    Machine,
    /// Only `HKCU` entries.
    User,
}

#[cfg(test)]
mod tests {
    use super::{Options, ScopeFilter};
    use clap::Parser;
    use pathdoc_core::{PathEntry, PathScope};

    fn entry(scope: PathScope) -> PathEntry {
        PathEntry {
            index: 0,
            scope,
            raw: r"C:\somewhere".to_owned(),
            expanded: None,
            value_kind: None,
            findings: Vec::new(),
        }
    }

    fn parse(args: &[&str]) -> Options {
        match Options::try_parse_from(std::iter::once("pathdoc").chain(args.iter().copied())) {
            Ok(options) => options,
            Err(err) => panic!("parsing {args:?} failed: {err}"),
        }
    }

    #[test]
    fn the_defaults_are_a_coloured_table_of_everything() {
        let options = parse(&[]);
        assert!(!options.json);
        assert!(!options.shadows_only);
        assert!(!options.no_color);
        assert_eq!(options.scope, ScopeFilter::All);
    }

    #[test]
    fn every_documented_flag_parses() {
        let options = parse(&[
            "--json",
            "--scope",
            "machine",
            "--shadows-only",
            "--no-color",
        ]);
        assert!(options.json);
        assert!(options.shadows_only);
        assert!(options.no_color);
        assert_eq!(options.scope, ScopeFilter::Machine);
    }

    #[test]
    fn scope_filters_by_origin() {
        let all = parse(&[]);
        let machine = parse(&["--scope", "machine"]);
        let user = parse(&["--scope", "user"]);

        for scope in [PathScope::Machine, PathScope::User, PathScope::ProcessOnly] {
            assert!(all.includes(&entry(scope)));
        }

        assert!(machine.includes(&entry(PathScope::Machine)));
        assert!(!machine.includes(&entry(PathScope::User)));
        // Runtime injection is neither machine nor user, so a scoped run omits it.
        assert!(!machine.includes(&entry(PathScope::ProcessOnly)));

        assert!(user.includes(&entry(PathScope::User)));
        assert!(!user.includes(&entry(PathScope::Machine)));
    }

    #[test]
    fn an_unknown_scope_is_rejected() {
        assert!(Options::try_parse_from(["pathdoc", "--scope", "registry"]).is_err());
    }

    #[test]
    fn nothing_here_offers_to_change_the_path() {
        // Slice 1 is read-only, and the surest way for that to erode is a flag
        // appearing before the design for backups and confirmation exists.
        for forbidden in ["--fix", "--write", "--repair", "--remove", "--dedupe"] {
            assert!(
                Options::try_parse_from(["pathdoc", forbidden]).is_err(),
                "{forbidden} must not be accepted"
            );
        }
    }
}
