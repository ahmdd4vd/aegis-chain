use aegis_core::AdvisorySource;
use semver::Version;
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AdvisoryError {
    #[error("advisory http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("advisory server returned {0}")]
    Status(u16),
    #[error("advisory parse error: {0}")]
    Parse(String),
}

#[derive(Debug, Deserialize)]
pub struct OsvVulnerability {
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,
    #[serde(default)]
    pub database_specific: OsvDatabaseSpecific,
}

#[derive(Debug, Deserialize)]
pub struct OsvSeverity {
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub score: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct OsvDatabaseSpecific {
    pub severity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVulnerability>,
}

pub const OSV_ENDPOINT: &str = "https://api.osv.dev/v1/query";

/// Advisory source backed by the OSV.dev API for the `crates.io` ecosystem.
pub struct OsvSource {
    endpoint: String,
}

impl Default for OsvSource {
    fn default() -> Self {
        Self {
            endpoint: OSV_ENDPOINT.to_string(),
        }
    }
}

impl OsvSource {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a source pointed at a custom endpoint (used for tests).
    pub fn with_endpoint(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
        }
    }

    /// Query OSV for every vulnerability affecting `name@version`.
    pub fn query(
        &self,
        name: &str,
        version: &Version,
    ) -> Result<Vec<OsvVulnerability>, AdvisoryError> {
        let body = serde_json::json!({
            "package": { "name": name, "ecosystem": "crates.io" },
            "version": version.to_string()
        });

        let response = reqwest::blocking::Client::new()
            .post(&self.endpoint)
            .json(&body)
            .send()?;

        let status = response.status();
        if !status.is_success() {
            return Err(AdvisoryError::Status(status.as_u16()));
        }

        let parsed: OsvResponse = response
            .json()
            .map_err(|error| AdvisoryError::Parse(error.to_string()))?;
        Ok(parsed.vulns)
    }
}

impl AdvisorySource for OsvSource {
    fn severity_for(&self, name: &str, version: &Version) -> Option<f64> {
        match self.query(name, version) {
            Ok(vulns) => {
                let score = normalize_vulns(&vulns);
                if score > 0.0 {
                    Some(score)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }
}

/// Aggregate the highest normalized severity (0..=1) across vulnerabilities.
pub fn normalize_vulns(vulns: &[OsvVulnerability]) -> f64 {
    vulns.iter().map(vuln_severity).fold(0.0, f64::max)
}

fn vuln_severity(vuln: &OsvVulnerability) -> f64 {
    for sev in &vuln.severity {
        let is_cvss = sev
            .kind
            .as_deref()
            .map(|kind| kind.contains("CVSS"))
            .unwrap_or(true);
        if is_cvss {
            if let Some(score_str) = &sev.score {
                if let Ok(value) = score_str.parse::<f64>() {
                    if (0.0..=10.0).contains(&value) {
                        return (value / 10.0).clamp(0.0, 1.0);
                    }
                }
            }
        }
    }

    if let Some(label) = &vuln.database_specific.severity {
        return label_severity(label);
    }

    0.0
}

fn label_severity(label: &str) -> f64 {
    match label.to_uppercase().as_str() {
        "LOW" => 0.2,
        "MODERATE" | "MEDIUM" => 0.4,
        "HIGH" => 0.7,
        "CRITICAL" => 0.9,
        _ => 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vuln_with_cvss(score: &str) -> OsvVulnerability {
        OsvVulnerability {
            severity: vec![OsvSeverity {
                kind: Some("CVSS_V3".to_string()),
                score: Some(score.to_string()),
            }],
            database_specific: OsvDatabaseSpecific { severity: None },
        }
    }

    fn vuln_with_label(label: &str) -> OsvVulnerability {
        OsvVulnerability {
            severity: vec![],
            database_specific: OsvDatabaseSpecific {
                severity: Some(label.to_string()),
            },
        }
    }

    #[test]
    fn cvss_score_is_normalized_to_tenth() {
        assert!((normalize_vulns(&[vuln_with_cvss("9.8")]) - 0.98).abs() < 1e-9);
        assert!((normalize_vulns(&[vuln_with_cvss("0.0")]) - 0.0).abs() < 1e-9);
    }

    #[test]
    fn highest_severity_wins_across_vulns() {
        let vulns = vec![vuln_with_cvss("4.0"), vuln_with_cvss("9.1")];
        assert!((normalize_vulns(&vulns) - 0.91).abs() < 1e-9);
    }

    #[test]
    fn label_severity_maps_to_bands() {
        assert!((normalize_vulns(&[vuln_with_label("LOW")]) - 0.2).abs() < 1e-9);
        assert!((normalize_vulns(&[vuln_with_label("HIGH")]) - 0.7).abs() < 1e-9);
        assert!((normalize_vulns(&[vuln_with_label("CRITICAL")]) - 0.9).abs() < 1e-9);
    }

    #[test]
    fn no_vulns_yields_zero() {
        assert_eq!(normalize_vulns(&[]), 0.0);
    }

    #[test]
    fn query_hits_osv_and_normalizes() {
        let mut server = mockito::Server::new();
        let body = serde_json::json!({
            "vulns": [{
                "id": "OSV-2024-0001",
                "severity": [{ "type": "CVSS_V3", "score": "7.5" }]
            }]
        });
        let _m = server
            .mock("POST", "/v1/query")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body.to_string())
            .create();

        let source = OsvSource::with_endpoint(format!("{}/v1/query", server.url()));
        let severity = source.severity_for("serde", &Version::new(1, 0, 0));
        assert_eq!(severity, Some(0.75));
    }

    #[test]
    fn empty_response_yields_no_finding() {
        let mut server = mockito::Server::new();
        let _m = server
            .mock("POST", "/v1/query")
            .with_status(200)
            .with_body("{\"vulns\": []}")
            .create();

        let source = OsvSource::with_endpoint(format!("{}/v1/query", server.url()));
        assert_eq!(source.severity_for("serde", &Version::new(1, 0, 0)), None);
    }
}
