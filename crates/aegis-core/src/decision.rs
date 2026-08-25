use crate::advisory::AdvisorySource;
use crate::provenance::ProvenanceSource;
use aegis_graph::analyze_impact;
use aegis_policy::{
    compute_score, decide as decide_action, required_evidence_for, run_rules, score_level, Action,
    EvalFacts, EvaluationTrace, EvidenceAvailability, Policy, ScoreComponents,
    RISK_FORMULA_VERSION,
};
use serde::{Deserialize, Serialize};

use crate::diff::{ChangeKind, PackageChange};
use crate::model::{DependencySnapshot, PackageKey};
use crate::pipeline;

pub const DECISION_REPORT_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeDecision {
    pub change: PackageChange,
    pub score: u8,
    pub level: String,
    pub status: Action,
    pub matched_rules: Vec<String>,
    pub traces: Vec<EvaluationTrace>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySummary {
    pub overall_status: Action,
    pub formula_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionReport {
    pub schema_version: u32,
    pub changes: Vec<PackageChange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicySummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub decisions: Vec<ChangeDecision>,
}

pub fn run_decision(
    base: &DependencySnapshot,
    head: &DependencySnapshot,
    policy: Option<&Policy>,
    evidence: &EvidenceAvailability,
    advisory: Option<&dyn AdvisorySource>,
    provenance: Option<&dyn ProvenanceSource>,
) -> DecisionReport {
    let diff = pipeline::run_diff(base, head);

    let Some(policy) = policy else {
        return DecisionReport {
            schema_version: DECISION_REPORT_SCHEMA_VERSION,
            changes: diff.changes,
            policy: None,
            decisions: Vec::new(),
        };
    };

    let base_graph = pipeline::graph_of(base);
    let head_graph = pipeline::graph_of(head);
    let mut decisions = Vec::new();

    for change in &diff.changes {
        let uses_head = change.after.is_some();
        let reference_snapshot = if uses_head { head } else { base };
        let reference_graph = if uses_head { &head_graph } else { &base_graph };

        let Some(changed_key) = change.after.as_ref().or(change.before.as_ref()) else {
            continue;
        };
        let changed_key: PackageKey = changed_key.clone();

        let impact = analyze_impact(
            reference_graph,
            &changed_key,
            &reference_snapshot.workspace_members,
        );

        let is_added = change.kind == ChangeKind::Added;
        let touches_critical = impact.impacted_roots.iter().any(|root| {
            policy
                .critical_packages
                .iter()
                .any(|critical| critical == &root.name)
        });

        let required = required_evidence_for(&policy.evidence, is_added, touches_critical);
        let mut available = evidence.get(&change.name).cloned().unwrap_or_default();
        if let Some(provenance) = provenance {
            if provenance.has_provenance(&change.name, &changed_key.version) {
                available.insert(aegis_policy::EvidenceKind::Provenance);
            }
        }
        let missing = required
            .iter()
            .filter(|kind| !available.contains(kind))
            .count();
        let evidence_gap = if required.is_empty() {
            0.0
        } else {
            missing as f64 / required.len() as f64
        };

        let member_count = reference_snapshot.workspace_members.len();
        let impact_breadth = if member_count == 0 {
            0.0
        } else {
            impact.impacted_roots.len() as f64 / member_count as f64
        };

        let proximity = if impact.root_distances.is_empty() {
            0.0
        } else {
            impact
                .root_distances
                .iter()
                .map(|distance| 1.0 / (1.0 + *distance as f64))
                .sum::<f64>()
                / impact.root_distances.len() as f64
        };

        let components = ScoreComponents {
            magnitude: magnitude_of(change.kind),
            impact_breadth,
            proximity,
            critical: if touches_critical { 1.0 } else { 0.0 },
            evidence_gap,
            findings: advisory_severity(change, advisory),
        };
        let score = compute_score(&components);

        let facts = EvalFacts {
            is_added,
            is_major_upgrade: change.kind == ChangeKind::MajorUpgrade,
            source_changed: change.kind == ChangeKind::SourceMutation,
            touches_critical,
            risk_score: score,
            available_evidence: available,
        };

        let traces: Vec<EvaluationTrace> = run_rules(policy, &facts);
        let status = decide_action(&traces);
        let matched_rules = traces
            .iter()
            .filter(|trace| trace.matched)
            .map(|trace| trace.rule_id.clone())
            .collect();

        decisions.push(ChangeDecision {
            change: change.clone(),
            score,
            level: score_level(score, &policy.thresholds).to_string(),
            status,
            matched_rules,
            traces,
        });
    }

    let overall_status = decisions
        .iter()
        .map(|decision| decision.status)
        .max()
        .unwrap_or(Action::Pass);

    DecisionReport {
        schema_version: DECISION_REPORT_SCHEMA_VERSION,
        changes: diff.changes,
        policy: Some(PolicySummary {
            overall_status,
            formula_version: RISK_FORMULA_VERSION.to_string(),
        }),
        decisions,
    }
}

fn magnitude_of(kind: ChangeKind) -> f64 {
    match kind {
        ChangeKind::PatchUpgrade => 0.15,
        ChangeKind::MinorUpgrade => 0.40,
        ChangeKind::MajorUpgrade => 0.75,
        ChangeKind::SourceMutation => 0.90,
        ChangeKind::Added | ChangeKind::Removed | ChangeKind::Downgrade => 0.60,
    }
}

fn advisory_severity(change: &PackageChange, advisory: Option<&dyn AdvisorySource>) -> f64 {
    let Some(advisory) = advisory else {
        return 0.0;
    };
    let Some(version) = change
        .after
        .as_ref()
        .or(change.before.as_ref())
        .map(|key| &key.version)
    else {
        return 0.0;
    };
    advisory.severity_for(&change.name, version).unwrap_or(0.0)
}
