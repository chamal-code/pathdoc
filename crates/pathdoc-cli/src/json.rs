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
        // Never filtered. Which copy of a name wins is decided across the whole
        // PATH, so a scope-narrowed answer would be wrong rather than narrower.
        executables: report.executables.clone(),
    };

    serde_json::to_writer_pretty(&mut *out, &envelope).map_err(io::Error::other)?;
    writeln!(out)
}

#[cfg(test)]
mod tests {
    use super::write_json;
    use pathdoc_core::{
        AuditReport, Capability, Finding, Intercept, JsonReport, Occurrence, PathEntry, PathScope,
        Resolved, ShellConstruct, ValueKind,
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
                    // Second in the live PATH, behind the injected shim.
                    process_position: Some(1),
                    findings: Vec::new(),
                },
                PathEntry {
                    index: 1,
                    scope: PathScope::User,
                    raw: r"C:\Users\Someone\nope".to_owned(),
                    expanded: None,
                    value_kind: Some(ValueKind::Sz),
                    // On PATH in the registry, but not in this process.
                    process_position: None,
                    findings: vec![Finding::Missing, Finding::Duplicate { first_seen_at: 0 }],
                },
                PathEntry {
                    index: 2,
                    scope: PathScope::ProcessOnly,
                    raw: r"C:\shim".to_owned(),
                    expanded: None,
                    value_kind: None,
                    // Injected at the front, which is the whole point of schema 3.
                    process_position: Some(0),
                    findings: Vec::new(),
                },
            ],
            executables: Vec::new(),
            capabilities: vec![Capability::Composition, Capability::EntryFindings],
        }
    }

    // Every assertion below is a promise to a consumer. Changing one means
    // bumping SCHEMA_VERSION, which is the point of pinning them here.

    #[test]
    fn the_envelope_carries_the_schema_version_and_capabilities() {
        let value = parse(&render(&sample(), false));

        assert_eq!(value["schemaVersion"], 4);
        assert_eq!(
            value["capabilities"],
            serde_json::json!(["composition", "entryFindings"])
        );
    }

    #[test]
    fn an_empty_executables_array_is_distinguishable_from_an_uncomputed_one() {
        let uncomputed = parse(&render(&sample(), false));
        assert_eq!(uncomputed["executables"], serde_json::json!([]));
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
        assert_eq!(clean["executables"], serde_json::json!([]));
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
    fn executable_fields_are_camel_case() {
        let mut report = sample();
        report.capabilities.push(Capability::ShadowDetection);
        report.executables = vec![Resolved {
            stem: "git".to_owned(),
            intercept: None,
            occurrences: vec![Occurrence {
                entry_index: 0,
                scope: PathScope::Machine,
                process_position: Some(1),
                directory: r"C:\Program Files\Git\cmd".to_owned(),
                file_name: "git.exe".to_owned(),
                is_reparse_point: true,
            }],
        }];

        let value = parse(&render(&report, false));
        let occurrence = &value["executables"][0]["occurrences"][0];

        assert_eq!(value["executables"][0]["stem"], "git");
        assert_eq!(occurrence["entryIndex"], 0);
        assert_eq!(occurrence["scope"], "machine");
        assert_eq!(occurrence["processPosition"], 1);
        assert_eq!(occurrence["directory"], r"C:\Program Files\Git\cmd");
        assert_eq!(occurrence["fileName"], "git.exe");
        assert_eq!(occurrence["isReparsePoint"], true);
    }

    #[test]
    fn an_entry_carries_its_live_position_or_null() {
        let value = parse(&render(&sample(), false));

        assert_eq!(value["entries"][0]["processPosition"], 1);
        // On PATH in the registry, absent from this process. Null, not missing, so
        // a typed consumer gets `number | null`.
        assert!(value["entries"][1].get("processPosition").is_some());
        assert!(value["entries"][1]["processPosition"].is_null());
        // Runtime injection goes to the front, which is the whole reason schema 3
        // exists.
        assert_eq!(value["entries"][2]["processPosition"], 0);
    }

    #[test]
    fn both_winners_are_derivable_from_the_json_alone() {
        // The documented rules: live winner is the first occurrence with a non-null
        // processPosition; fresh winner is the lowest entryIndex among occurrences
        // whose scope is not processOnly.
        let mut report = sample();
        report.capabilities.push(Capability::ShadowDetection);
        report.executables = vec![Resolved {
            stem: "node".to_owned(),
            intercept: None,
            occurrences: vec![
                Occurrence {
                    entry_index: 2,
                    scope: PathScope::ProcessOnly,
                    process_position: Some(0),
                    directory: r"C:\shim".to_owned(),
                    file_name: "node.exe".to_owned(),
                    is_reparse_point: false,
                },
                Occurrence {
                    entry_index: 1,
                    scope: PathScope::User,
                    process_position: Some(5),
                    directory: r"C:\registry".to_owned(),
                    file_name: "node.exe".to_owned(),
                    is_reparse_point: false,
                },
            ],
        }];

        let value = parse(&render(&report, false));
        let occurrences = match value["executables"][0]["occurrences"].as_array() {
            Some(occurrences) => occurrences.clone(),
            None => panic!("occurrences was not an array"),
        };

        let live = occurrences
            .iter()
            .find(|occurrence| !occurrence["processPosition"].is_null());
        assert_eq!(
            live.map(|occurrence| occurrence["directory"].clone()),
            Some(serde_json::json!(r"C:\shim"))
        );

        let fresh = occurrences
            .iter()
            .filter(|occurrence| occurrence["scope"] != "processOnly")
            .min_by_key(|occurrence| occurrence["entryIndex"].as_u64().unwrap_or(u64::MAX));
        assert_eq!(
            fresh.map(|occurrence| occurrence["directory"].clone()),
            Some(serde_json::json!(r"C:\registry"))
        );
    }

    #[test]
    fn an_occurrence_stands_alone_without_the_entries_array() {
        // The reason `directory` is denormalised: under `--shadows-only` there are
        // no entries to join against at all.
        let mut report = sample();
        report.capabilities.push(Capability::ShadowDetection);
        report.executables = vec![Resolved {
            stem: "gzip".to_owned(),
            intercept: None,
            occurrences: vec![Occurrence {
                entry_index: 17,
                scope: PathScope::User,
                process_position: Some(17),
                directory: r"C:\Users\Someone\vendored\usr\bin".to_owned(),
                file_name: "gzip.exe".to_owned(),
                is_reparse_point: false,
            }],
        }];

        let value = parse(&render(&report, true));

        assert_eq!(value["entries"], serde_json::json!([]));
        assert_eq!(
            value["executables"][0]["occurrences"][0]["directory"],
            r"C:\Users\Someone\vendored\usr\bin"
        );
    }

    #[test]
    fn an_intercept_is_camel_case_and_names_the_interpreter_absolutely() {
        let mut report = sample();
        report.capabilities.push(Capability::ShadowDetection);
        report.capabilities.push(Capability::ShellMasking);
        report.executables = vec![Resolved {
            stem: "sc".to_owned(),
            intercept: Some(Intercept {
                construct: ShellConstruct::Alias,
                resolves_to: Some("Set-Content".to_owned()),
                interpreter: r"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe"
                    .to_owned(),
                profile_loaded: false,
            }),
            occurrences: vec![Occurrence {
                entry_index: 0,
                scope: PathScope::Machine,
                process_position: Some(1),
                directory: r"C:\WINDOWS\system32".to_owned(),
                file_name: "sc.exe".to_owned(),
                is_reparse_point: false,
            }],
        }];

        let value = parse(&render(&report, false));
        let intercept = &value["executables"][0]["intercept"];

        assert_eq!(intercept["construct"], "alias");
        assert_eq!(intercept["resolvesTo"], "Set-Content");
        // Absolute path, not a shell name: the verdict differs between interpreters,
        // so "PowerShell" would be ambiguous exactly where it matters.
        assert_eq!(
            intercept["interpreter"],
            r"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe"
        );
        assert_eq!(intercept["profileLoaded"], false);
    }

    #[test]
    fn a_function_intercept_has_a_null_target() {
        let mut report = sample();
        report.capabilities.push(Capability::ShellMasking);
        report.executables = vec![Resolved {
            stem: "more".to_owned(),
            intercept: Some(Intercept {
                construct: ShellConstruct::Function,
                resolves_to: None,
                interpreter: r"C:\WINDOWS\powershell.exe".to_owned(),
                profile_loaded: true,
            }),
            occurrences: Vec::new(),
        }];

        let intercept = parse(&render(&report, false))["executables"][0]["intercept"].clone();

        assert_eq!(intercept["construct"], "function");
        // A function is its own definition, so `string | null` and not a fake target.
        assert!(intercept.get("resolvesTo").is_some());
        assert!(intercept["resolvesTo"].is_null());
        assert_eq!(intercept["profileLoaded"], true);
    }

    #[test]
    fn a_null_intercept_is_distinguishable_from_an_unchecked_scan() {
        // The whole reason ShellMasking is a capability. Same shape as the shadow
        // case, and the mistake it prevents is reporting "nothing masks this" when
        // nothing was asked.
        let unchecked = parse(&render(&sample(), false));
        assert!(
            !unchecked["capabilities"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|capability| capability == "shellMasking"),
            "a run that did not scan must not claim shellMasking"
        );

        let mut scanned = sample();
        scanned.capabilities.push(Capability::ShellMasking);
        scanned.executables = vec![Resolved {
            stem: "gzip".to_owned(),
            intercept: None,
            occurrences: Vec::new(),
        }];
        let value = parse(&render(&scanned, false));

        assert!(
            value["capabilities"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|capability| capability == "shellMasking")
        );
        // Now, and only now, does a null intercept mean "nothing masks it".
        assert!(value["executables"][0]["intercept"].is_null());
    }

    #[test]
    fn shadows_only_empties_the_entries_without_removing_the_field() {
        let value = parse(&render(&sample(), true));

        assert_eq!(value["entries"], serde_json::json!([]));
        assert_eq!(value["schemaVersion"], 4);
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
