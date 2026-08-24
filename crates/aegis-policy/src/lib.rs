use std::collections::{BTreeMap, BTreeSet};

pub mod evaluate;
pub mod rules;
pub mod schema;
pub mod score;

pub use evaluate::{
    decide, evaluate_expr, run_rules, Action, EvalFacts, EvaluationTrace, Expr, PredicateTrace,
};
pub use rules::{parse_policy, required_evidence_for, Rule, Thresholds};
pub use schema::{
    AnalysisConfig, EvidenceConfig, EvidenceKind, Policy, PolicyError, POLICY_SCHEMA_VERSION,
};
pub use score::{compute_score, score_level, ScoreComponents, RISK_FORMULA_VERSION};

pub type EvidenceAvailability = BTreeMap<String, BTreeSet<EvidenceKind>>;
