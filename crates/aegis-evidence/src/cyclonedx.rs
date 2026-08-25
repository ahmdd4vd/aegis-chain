use std::path::Path;

use aegis_policy::{EvidenceAvailability, EvidenceKind};
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error("failed to read SBOM file {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to parse CycloneDX BOM: {0}")]
    Parse(String),
}

#[derive(Debug, Deserialize)]
struct Bom {
    #[serde(default)]
    components: Vec<BomComponent>,
}

#[derive(Debug, Deserialize)]
struct BomComponent {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    purl: Option<String>,
    #[serde(default)]
    hashes: Vec<BomHash>,
    #[serde(default)]
    licenses: Vec<BomLicense>,
}

#[derive(Debug, Deserialize)]
struct BomHash {
    content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BomLicense {
    #[serde(default)]
    license: Option<BomLicenseId>,
    #[serde(default)]
    expression: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BomLicenseId {
    #[serde(default)]
    id: Option<String>,
}

fn parse_bom(content: &str) -> Result<Vec<BomComponent>, EvidenceError> {
    let content = strip_bom(content);
    serde_json::from_str::<Bom>(content)
        .map(|bom| bom.components)
        .map_err(|error| EvidenceError::Parse(error.to_string()))
}

fn strip_bom(input: &str) -> &str {
    match input.as_bytes() {
        [0xEF, 0xBB, 0xBF, rest @ ..] => {
            let offset = input.len() - rest.len();
            &input[offset..]
        }
        _ => input,
    }
}

/// Extract `(name, version)` from a `pkg:cargo/name@version` PURL, ignoring
/// qualifiers (`?...`). Returns `None` for non-cargo or malformed PURLs.
fn parse_cargo_purl(purl: &str) -> Option<(String, Option<String>)> {
    let rest = purl.strip_prefix("pkg:cargo/")?;
    let without_qualifiers = rest.split('?').next().unwrap_or(rest);
    let (name, version) = match without_qualifiers.split_once('@') {
        Some((name, version)) => (name.to_string(), Some(version.to_string())),
        None => (without_qualifiers.to_string(), None),
    };
    if name.is_empty() {
        None
    } else {
        Some((name, version))
    }
}

/// Resolve the package key for evidence matching: prefer the cargo PURL,
/// fall back to the bare `name` field.
fn component_key(component: &BomComponent) -> Option<String> {
    if let Some(purl) = &component.purl {
        if let Some((name, _)) = parse_cargo_purl(purl) {
            return Some(name);
        }
    }
    component.name.clone().filter(|name| !name.is_empty())
}

fn availability_from_components(components: Vec<BomComponent>) -> EvidenceAvailability {
    let mut availability = EvidenceAvailability::new();
    for component in components {
        let Some(key) = component_key(&component) else {
            continue;
        };
        if component.version.is_none() && component.purl.is_none() {
            continue;
        }
        let entry = availability.entry(key).or_default();
        entry.insert(EvidenceKind::Sbom);
        if component.hashes.iter().any(|hash| hash.content.is_some()) {
            entry.insert(EvidenceKind::Hashes);
        }
        let has_license = component.licenses.iter().any(|license| {
            license
                .license
                .as_ref()
                .map(|id| id.id.is_some())
                .unwrap_or(false)
                || license.expression.is_some()
        });
        if has_license {
            entry.insert(EvidenceKind::License);
        }
    }
    availability
}

pub fn availability_from_bom_content(content: &str) -> Result<EvidenceAvailability, EvidenceError> {
    Ok(availability_from_components(parse_bom(content)?))
}

pub fn availability_from_bom_files(paths: &[&Path]) -> Result<EvidenceAvailability, EvidenceError> {
    let mut combined = EvidenceAvailability::new();

    for path in paths {
        let display = path.display().to_string();
        let bytes = std::fs::read(path).map_err(|source| EvidenceError::Io {
            path: display.clone(),
            source,
        })?;
        let bytes = strip_bom_prefix(&bytes);
        let content = String::from_utf8(bytes.to_vec()).map_err(|error| {
            EvidenceError::Parse(format!("{} is not valid UTF-8: {error}", display))
        })?;

        for (package, kinds) in availability_from_bom_content(&content)? {
            combined.entry(package).or_default().extend(kinds);
        }
    }

    Ok(combined)
}

fn strip_bom_prefix(bytes: &[u8]) -> &[u8] {
    match bytes {
        [0xEF, 0xBB, 0xBF, rest @ ..] => rest,
        _ => bytes,
    }
}
