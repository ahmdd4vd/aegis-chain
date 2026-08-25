use std::path::Path;

use aegis_evidence::{availability_from_bom_content, availability_from_bom_files};
use aegis_policy::EvidenceKind;

const FIXTURE_BOM: &str = include_str!("../../../fixtures/sbom/bom.json");

#[test]
fn parses_components_and_maps_sbom_evidence_by_name() {
    let availability = availability_from_bom_content(FIXTURE_BOM).expect("fixture bom parses");

    let unicode = availability
        .get("unicode-width")
        .expect("unicode-width present");
    assert!(unicode.contains(&EvidenceKind::Sbom));

    let semver = availability.get("semver").expect("semver present");
    assert!(semver.contains(&EvidenceKind::Sbom));

    assert!(
        !availability.contains_key("no-version-component"),
        "components without version/purl must be ignored"
    );
}

#[test]
fn invalid_bom_content_is_rejected() {
    assert!(availability_from_bom_content("{ not json").is_err());
}

#[test]
fn loads_multiple_files_and_merges() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/sbom/bom.json");
    let combined = availability_from_bom_files(&[&path, &path]).expect("loads fixture");

    let semver = combined.get("semver").expect("semver present after merge");
    assert!(semver.contains(&EvidenceKind::Sbom));
}

#[test]
fn tolerates_utf8_bom_prefix() {
    let with_bom = format!("\u{feff}{FIXTURE_BOM}");
    let availability = availability_from_bom_content(&with_bom).expect("bom with BOM parses");
    assert!(availability.contains_key("semver"));
}

#[test]
fn maps_evidence_by_cargo_purl_when_name_absent() {
    let bom = r#"{
      "components": [
        { "type": "library", "purl": "pkg:cargo/serde@1.0.210" }
      ]
    }"#;
    let availability = availability_from_bom_content(bom).expect("bom parses");
    let serde = availability.get("serde").expect("serde resolved from purl");
    assert!(serde.contains(&EvidenceKind::Sbom));
}

#[test]
fn maps_hashes_and_license_evidence() {
    let bom = r#"{
      "components": [
        {
          "type": "library",
          "name": "cached",
          "version": "0.51.0",
          "purl": "pkg:cargo/cached@0.51.0",
          "hashes": [ { "alg": "SHA-256", "content": "abc123" } ],
          "licenses": [ { "license": { "id": "MIT" } } ]
        }
      ]
    }"#;
    let availability = availability_from_bom_content(bom).expect("bom parses");
    let cached = availability.get("cached").expect("cached present");
    assert!(cached.contains(&EvidenceKind::Sbom));
    assert!(cached.contains(&EvidenceKind::Hashes));
    assert!(cached.contains(&EvidenceKind::License));
}

#[test]
fn non_cargo_purl_falls_back_to_name() {
    let bom = r#"{
      "components": [
        { "type": "library", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21" }
      ]
    }"#;
    let availability = availability_from_bom_content(bom).expect("bom parses");
    assert!(
        availability.contains_key("lodash"),
        "non-cargo purl should fall back to name"
    );
    assert!(!availability.contains_key("lodash@4.17.21"));
}

#[test]
fn cargo_purl_with_qualifiers_resolves_name() {
    let bom = r#"{ "components": [ { "type": "library", "purl": "pkg:cargo/serde@1.0.210?arch=x86_64" } ] }"#;
    let availability = availability_from_bom_content(bom).expect("bom parses");
    assert!(availability.contains_key("serde"));
}
