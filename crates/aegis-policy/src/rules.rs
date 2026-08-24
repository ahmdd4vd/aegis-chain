use serde::Deserialize;

use super::schema::{EvidenceConfig, Policy, PolicyError, POLICY_SCHEMA_VERSION};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Thresholds {
    #[serde(default = "default_warn_at")]
    pub warn_at: u8,
    #[serde(default = "default_high_at")]
    pub high_at: u8,
    #[serde(default = "default_block_at")]
    pub block_at: u8,
}

fn default_warn_at() -> u8 {
    30
}

fn default_high_at() -> u8 {
    60
}

fn default_block_at() -> u8 {
    80
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            warn_at: default_warn_at(),
            high_at: default_high_at(),
            block_at: default_block_at(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub when: super::evaluate::Expr,
    pub action: super::evaluate::Action,
    #[serde(default)]
    pub message: Option<String>,
}

pub fn parse_policy(input: &str) -> Result<Policy, PolicyError> {
    let policy: Policy = serde_yaml::from_str(input).map_err(|error| {
        PolicyError::Parse(format!(
            "{} at line {}, column {}",
            error,
            error.location().map(|l| l.line()).unwrap_or(0),
            error.location().map(|l| l.column()).unwrap_or(0)
        ))
    })?;

    validate_policy(&policy)?;

    Ok(policy)
}

fn validate_policy(policy: &Policy) -> Result<(), PolicyError> {
    if policy.schema_version != POLICY_SCHEMA_VERSION {
        return Err(PolicyError::Schema(format!(
            "unsupported schema_version {}; expected {}",
            policy.schema_version, POLICY_SCHEMA_VERSION
        )));
    }

    let thresholds = policy.thresholds;
    if !(thresholds.warn_at <= thresholds.high_at && thresholds.high_at <= thresholds.block_at) {
        return Err(PolicyError::Thresholds(format!(
            "expected warn_at <= high_at <= block_at, got {} / {} / {}",
            thresholds.warn_at, thresholds.high_at, thresholds.block_at
        )));
    }

    let mut seen = std::collections::BTreeSet::new();
    for rule in &policy.rules {
        if !seen.insert(rule.id.as_str()) {
            return Err(PolicyError::DuplicateRuleId(rule.id.clone()));
        }
    }

    Ok(())
}

pub fn required_evidence_for(
    evidence: &EvidenceConfig,
    is_added: bool,
    touches_critical: bool,
) -> Vec<super::schema::EvidenceKind> {
    let mut required = Vec::new();
    if is_added {
        required.extend(evidence.require_for_added_packages.iter().copied());
    }
    if touches_critical {
        required.extend(evidence.require_for_critical_path.iter().copied());
    }
    required.sort();
    required.dedup();
    required
}
