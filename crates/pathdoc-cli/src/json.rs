//! JSON rendering.
//!
//! The shape itself is [`pathdoc_core::JsonReport`], defined once in the core so
//! that a GUI linking the library and a script parsing this output are looking at
//! the same contract. All this module decides is pretty-printing and which
//! entries go in.

use std::io::{self, Write};

use pathdoc_core::{AuditReport, JsonReport, PathEntry, SCHEMA_VERSION};

/// Write the report as pretty-printed JSON, newline-terminated.
///
/// `entries` is already filtered by `--scope`. Under `--shadows-only` the entries
/// array is empty rather than absent, so the shape does not change with the
/// flags used to produce it.
pub(crate) fn write_json(
    out: &mut impl Write,
    report: &AuditReport,
    entries: &[&PathEntry],
    shadows_only: bool,
) -> io::Result<()> {
    let envelope = JsonReport {
        schema_version: SCHEMA_VERSION,
        capabilities: report.capabilities.clone(),
        entries: if shadows_only {
            Vec::new()
        } else {
            entries.iter().map(|entry| (*entry).clone()).collect()
        },
        shadows: report.shadows.clone(),
    };

    serde_json::to_writer_pretty(&mut *out, &envelope).map_err(io::Error::other)?;
    writeln!(out)
}

#[cfg(test)]
mod tests {
    use super::write_json;
    use pathdoc_core::{
        AuditReport, Capability, Finding, JsonReport, Occurrence, PathEntry, PathScope, Shadowed,
        ValueKind,
    };

    fn render(report: &AuditReport, shadows_only: bool) -> String {
        let entries: Vec<&PathEntry> = report.entries.iter().collect();
        let mut buffer = Vec::new();
        if let Err(err) = write_json(&mut buffer, report, &entries, shadows_only) {
            panic!("rendering failed: {err}");
        }
        match String::from_utf8(buffer) {
            Ok(text) => text,
            Err(err) => panic!("output was not utf-8: {err}"),
        }
    }

    fn parse(text: &str) -> serde_json::Value {
        match serde_json::from_str(text) {
            Ok(value) => value,
            Err(err) => panic!("output was not valid json: {err}"),
        }
    }

    fn sample() -> AuditReport {
        AuditReport {
            entries: vec![
                PathEntry {
                    index: 0,
                    scope: PathScope::Machine,
                    raw: r"%SystemRoot%\system32".to_owned(),
                    expanded: Some(r"C:\WINDOWS\system32".to_owned()),
                    value_kind: Some(ValueKind::ExpandSz),
                    findings: Vec::new(),
                },
                PathEntry {
                    index: 1,
                    scope: PathScope::User,
                    raw: r"C:\Users\Someone\nope".to_owned(),
                    expanded: None,
                    value_kind: Some(ValueKind::Sz),
                    findings: vec![Finding::Missing, Finding::Duplicate { first_seen_at: 0 }],
                },
                PathEntry {
                    index: 2,
                    scope: PathScope::ProcessOnly,
                    raw: r"C:\shim".to_owned(),
                    expanded: None,
                    value_kind: None,
                    findings: Vec::new(),
                },
            ],
            shadows: Vec::new(),
            capabilities: vec![Capability::Composition, Capability::EntryFindings],
        }
    }

    // Every assertion below is a promise to a consumer. Changing one means
    // bumping SCHEMA_VERSION, which is the point of pinning them here.

    #[test]
    fn the_envelope_carries_the_schema_version_and_capabilities() {
        let value = parse(&render(&sample(), false));

        assert_eq!(value["schemaVersion"], 1);
        assert_eq!(
            value["capabilities"],
            serde_json::json!(["composition", "entryFindings"])
        );
    }

    #[test]
    fn an_empty_shadow_array_is_distinguishable_from_an_uncomputed_one() {
        let uncomputed = parse(&render(&sample(), false));
        assert_eq!(uncomputed["shadows"], serde_json::json!([]));
        assert!(
            !uncomputed["capabilities"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|capability| capability == "shadowDetection"),
            "an uncomputed run must not claim shadowDetection"
        );

        let mut computed = sample();
        computed.capabilities.push(Capability::ShadowDetection);
        let clean = parse(&render(&computed, false));
        assert_eq!(clean["shadows"], serde_json::json!([]));
        assert_eq!(
            clean["capabilities"],
            serde_json::json!(["composition", "entryFindings", "shadowDetection"])
        );
    }

    #[test]
    fn entry_fields_are_camel_case() {
        let value = parse(&render(&sample(), false));
        let entry = &value["entries"][0];

        assert_eq!(entry["index"], 0);
        assert_eq!(entry["scope"], "machine");
        assert_eq!(entry["raw"], r"%SystemRoot%\system32");
        assert_eq!(entry["expanded"], r"C:\WINDOWS\system32");
        assert_eq!(entry["valueKind"], "REG_EXPAND_SZ");
        assert_eq!(entry["findings"], serde_json::json!([]));
    }

    #[test]
    fn the_registry_value_type_is_reported_by_its_real_name() {
        let value = parse(&render(&sample(), false));

        assert_eq!(value["entries"][0]["valueKind"], "REG_EXPAND_SZ");
        assert_eq!(value["entries"][1]["valueKind"], "REG_SZ");
        // Runtime injection came from no registry value at all.
        assert!(value["entries"][2]["valueKind"].is_null());
        assert_eq!(value["entries"][2]["scope"], "processOnly");
    }

    #[test]
    fn an_absent_expansion_is_null_rather_than_missing() {
        let value = parse(&render(&sample(), false));

        // A typed consumer gets `string | null`, not `string | undefined`.
        assert!(value["entries"][1].get("expanded").is_some());
        assert!(value["entries"][1]["expanded"].is_null());
    }

    #[test]
    fn findings_are_a_discriminated_union() {
        let value = parse(&render(&sample(), false));
        let findings = &value["entries"][1]["findings"];

        assert_eq!(findings[0], serde_json::json!({ "kind": "missing" }));
        assert_eq!(
            findings[1],
            serde_json::json!({ "kind": "duplicate", "firstSeenAt": 0 })
        );
    }

    #[test]
    fn shadow_fields_are_camel_case() {
        let mut report = sample();
        report.capabilities.push(Capability::ShadowDetection);
        report.shadows = vec![Shadowed {
            stem: "git".to_owned(),
            occurrences: vec![Occurrence {
                entry_index: 0,
                file_name: "git.exe".to_owned(),
                is_reparse_point: true,
            }],
        }];

        let value = parse(&render(&report, false));
        let occurrence = &value["shadows"][0]["occurrences"][0];

        assert_eq!(value["shadows"][0]["stem"], "git");
        assert_eq!(occurrence["entryIndex"], 0);
        assert_eq!(occurrence["fileName"], "git.exe");
        assert_eq!(occurrence["isReparsePoint"], true);
    }

    #[test]
    fn shadows_only_empties_the_entries_without_removing_the_field() {
        let value = parse(&render(&sample(), true));

        assert_eq!(value["entries"], serde_json::json!([]));
        assert_eq!(value["schemaVersion"], 1);
    }

    #[test]
    fn the_contract_round_trips_through_rust() {
        // A Rust consumer shelling out should be able to read its own output back.
        let text = render(&sample(), false);
        let decoded: JsonReport = match serde_json::from_str(&text) {
            Ok(decoded) => decoded,
            Err(err) => panic!("could not deserialise our own output: {err}"),
        };

        assert_eq!(decoded, JsonReport::from(sample()));
    }

    #[test]
    fn indices_survive_scope_filtering() {
        let report = sample();
        // Only the user-scope entry, as `--scope user` would give.
        let entries: Vec<&PathEntry> = report
            .entries
            .iter()
            .filter(|entry| entry.scope == PathScope::User)
            .collect();
        let mut buffer = Vec::new();
        if let Err(err) = write_json(&mut buffer, &report, &entries, false) {
            panic!("rendering failed: {err}");
        }
        let value = parse(&String::from_utf8_lossy(&buffer));

        assert_eq!(value["entries"].as_array().map(Vec::len), Some(1));
        // Still index 1, not renumbered to 0.
        assert_eq!(value["entries"][0]["index"], 1);
    }
}
