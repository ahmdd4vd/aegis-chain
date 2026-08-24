use serde::Deserialize;
use thiserror::Error;

use super::rules::{Rule, Thresholds};

pub const POLICY_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy parse error: {0}")]
    Parse(String),
    #[error("policy schema error: {0}")]
    Schema(String),
    #[error("duplicate rule id: {0}")]
    DuplicateRuleId(String),
    #[error("invalid thresholds: {0}")]
    Thresholds(String),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema_version: u32,
    #[serde(default)]
    pub analysis: AnalysisConfig,
    #[serde(default)]
    pub critical_packages: Vec<String>,
    #[serde(default)]
    pub evidence: EvidenceConfig,
    #[serde(default)]
    pub thresholds: Thresholds,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct AnalysisConfig {
    pub mode: Option<AnalysisMode>,
    pub include_dev_dependencies: Option<bool>,
    pub include_build_dependencies: Option<bool>,
    pub max_paths_per_change: Option<usize>,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            mode: Some(AnalysisMode::Offline),
            include_dev_dependencies: Some(false),
            include_build_dependencies: Some(true),
            max_paths_per_change: Some(5),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisMode {
    Offline,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceConfig {
    #[serde(default, rename = "require_for_added_packages")]
    pub require_for_added_packages: Vec<EvidenceKind>,
    #[serde(default, rename = "require_for_critical_path")]
    pub require_for_critical_path: Vec<EvidenceKind>,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceKind {
    Sbom,
    Provenance,
    ApprovedSource,
    VulnerabilityFeed,
}
