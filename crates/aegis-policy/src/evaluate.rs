use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::rules::Rule;
use crate::schema::{EvidenceKind, Policy};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Pass,
    Warn,
    Block,
}

impl Action {
    pub fn label(&self) -> &'static str {
        match self {
            Action::Pass => "pass",
            Action::Warn => "warn",
            Action::Block => "block",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Expr {
    All(Vec<Expr>),
    Any(Vec<Expr>),
    Not(Box<Expr>),
    IsAdded(bool),
    IsMajorUpgrade(bool),
    SourceChanged(bool),
    TouchesCritical(bool),
    MissingEvidence(EvidenceKind),
    RiskAtLeast(u8),
}

const EXPR_KEYS: &[&str] = &[
    "all",
    "any",
    "not",
    "is_added",
    "is_major_upgrade",
    "source_changed",
    "touches_critical",
    "missing_evidence",
    "risk_at_least",
];

impl<'de> serde::Deserialize<'de> for Expr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ExprVisitor;

        impl<'de> serde::de::Visitor<'de> for ExprVisitor {
            type Value = Expr;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("an expression object with exactly one key")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                use serde::de::Error;

                let mut parsed: Option<Expr> = None;
                while let Some(key) = map.next_key::<String>()? {
                    let value = match key.as_str() {
                        "all" => Expr::All(map.next_value()?),
                        "any" => Expr::Any(map.next_value()?),
                        "not" => Expr::Not(Box::new(map.next_value()?)),
                        "is_added" => Expr::IsAdded(map.next_value()?),
                        "is_major_upgrade" => Expr::IsMajorUpgrade(map.next_value()?),
                        "source_changed" => Expr::SourceChanged(map.next_value()?),
                        "touches_critical" => Expr::TouchesCritical(map.next_value()?),
                        "missing_evidence" => Expr::MissingEvidence(map.next_value()?),
                        "risk_at_least" => Expr::RiskAtLeast(map.next_value()?),
                        unknown => {
                            return Err(A::Error::unknown_field(unknown, EXPR_KEYS));
                        }
                    };
                    if parsed.replace(value).is_some() {
                        return Err(A::Error::custom(
                            "expression object must contain exactly one key",
                        ));
                    }
                }
                parsed.ok_or_else(|| {
                    A::Error::custom("expression object must contain exactly one key")
                })
            }
        }

        deserializer.deserialize_map(ExprVisitor)
    }
}

#[derive(Debug, Clone, Default)]
pub struct EvalFacts {
    pub is_added: bool,
    pub is_major_upgrade: bool,
    pub source_changed: bool,
    pub touches_critical: bool,
    pub risk_score: u8,
    pub available_evidence: BTreeSet<EvidenceKind>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredicateTrace {
    pub label: String,
    pub matched: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationTrace {
    pub rule_id: String,
    pub matched: bool,
    pub action: Action,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub predicates: Vec<PredicateTrace>,
}

fn evidence_label(kind: EvidenceKind) -> &'static str {
    match kind {
        EvidenceKind::Sbom => "sbom",
        EvidenceKind::Provenance => "provenance",
        EvidenceKind::ApprovedSource => "approved_source",
        EvidenceKind::VulnerabilityFeed => "vulnerability_feed",
        EvidenceKind::Hashes => "hashes",
        EvidenceKind::License => "license",
    }
}

fn eval_leaf(expr: &Expr, facts: &EvalFacts) -> (String, bool) {
    match expr {
        Expr::IsAdded(expected) => ("is_added".to_string(), facts.is_added == *expected),
        Expr::IsMajorUpgrade(expected) => (
            "is_major_upgrade".to_string(),
            facts.is_major_upgrade == *expected,
        ),
        Expr::SourceChanged(expected) => (
            "source_changed".to_string(),
            facts.source_changed == *expected,
        ),
        Expr::TouchesCritical(expected) => (
            "touches_critical".to_string(),
            facts.touches_critical == *expected,
        ),
        Expr::MissingEvidence(kind) => (
            format!("missing_evidence({})", evidence_label(*kind)),
            !facts.available_evidence.contains(kind),
        ),
        Expr::RiskAtLeast(threshold) => (
            format!("risk_at_least({threshold})"),
            facts.risk_score >= *threshold,
        ),
        Expr::All(_) | Expr::Any(_) | Expr::Not(_) => {
            unreachable!("combinators handled by evaluate_expr")
        }
    }
}

pub fn evaluate_expr(expr: &Expr, facts: &EvalFacts, trace: &mut Vec<PredicateTrace>) -> bool {
    match expr {
        Expr::All(terms) => terms.iter().all(|term| evaluate_expr(term, facts, trace)),
        Expr::Any(terms) => terms.iter().any(|term| evaluate_expr(term, facts, trace)),
        Expr::Not(term) => !evaluate_expr(term, facts, trace),
        leaf => {
            let (label, matched) = eval_leaf(leaf, facts);
            trace.push(PredicateTrace { label, matched });
            matched
        }
    }
}

pub fn run_rules(policy: &Policy, facts: &EvalFacts) -> Vec<EvaluationTrace> {
    policy
        .rules
        .iter()
        .map(|rule: &Rule| {
            let mut predicates = Vec::new();
            let matched = evaluate_expr(&rule.when, facts, &mut predicates);
            EvaluationTrace {
                rule_id: rule.id.clone(),
                matched,
                action: rule.action,
                message: rule.message.clone(),
                predicates,
            }
        })
        .collect()
}

pub fn decide(traces: &[EvaluationTrace]) -> Action {
    traces
        .iter()
        .filter(|trace| trace.matched)
        .map(|trace| trace.action)
        .max()
        .unwrap_or(Action::Pass)
}
