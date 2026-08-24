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
    name: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    purl: Option<String>,
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

fn availability_from_components(components: Vec<BomComponent>) -> EvidenceAvailability {
    let mut availability = EvidenceAvailability::new();
    for component in components {
        if component.version.is_none() && component.purl.is_none() {
            continue;
        }
        availability
            .entry(component.name)
            .or_default()
            .insert(EvidenceKind::Sbom);
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
