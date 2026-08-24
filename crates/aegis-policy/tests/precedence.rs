use std::collections::BTreeSet;

use aegis_policy::{decide, parse_policy, run_rules, Action, EvalFacts};

fn facts_with(is_added: bool, touches_critical: bool, score: u8) -> EvalFacts {
    EvalFacts {
        is_added,
        is_major_upgrade: false,
        source_changed: false,
        touches_critical,
        risk_score: score,
        available_evidence: BTreeSet::new(),
    }
}

#[test]
fn block_wins_over_matched_warn() {
    let yaml = "
schema_version: 1
rules:
  - id: warn-on-added
    when: { is_added: true }
    action: warn
  - id: block-on-critical
    when: { touches_critical: true }
    action: block
";
    let policy = parse_policy(yaml).expect("policy parses");
    let traces = run_rules(&policy, &facts_with(true, true, 10));

    assert_eq!(decide(&traces), Action::Block);
    assert!(traces.iter().all(|trace| trace.matched));
}

#[test]
fn warn_when_only_warn_matches() {
    let yaml = "
schema_version: 1
rules:
  - id: warn-on-added
    when: { is_added: true }
    action: warn
  - id: block-on-critical
    when: { touches_critical: true }
    action: block
";
    let policy = parse_policy(yaml).unwrap();
    let traces = run_rules(&policy, &facts_with(true, false, 10));

    assert_eq!(decide(&traces), Action::Warn);

    let block_trace = traces
        .iter()
        .find(|trace| trace.rule_id == "block-on-critical")
        .unwrap();
    assert!(!block_trace.matched);
    assert_eq!(
        block_trace.predicates[0].label,
        "touches_critical".to_string()
    );
    assert!(!block_trace.predicates[0].matched);
}

#[test]
fn pass_when_nothing_matches() {
    let yaml = "
schema_version: 1
rules:
  - id: warn-on-added
    when: { is_added: true }
    action: warn
";
    let policy = parse_policy(yaml).unwrap();
    let traces = run_rules(&policy, &facts_with(false, false, 5));

    assert_eq!(decide(&traces), Action::Pass);
}

#[test]
fn all_requires_every_predicate_and_any_requires_one() {
    let yaml = "
schema_version: 1
rules:
  - id: strict
    when:
      all:
        - { is_added: true }
        - { touches_critical: true }
    action: block
  - id: loose
    when:
      any:
        - { is_added: false }
        - { risk_at_least: 50 }
    action: warn
";
    let policy = parse_policy(yaml).unwrap();

    let both = run_rules(&policy, &facts_with(true, true, 80));
    assert_eq!(decide(&both), Action::Block);

    let neither_all_but_any = run_rules(&policy, &facts_with(false, false, 80));
    assert_eq!(decide(&neither_all_but_any), Action::Warn);
}

#[test]
fn not_negates_leaf_predicate() {
    let yaml = "
schema_version: 1
rules:
  - id: warn-if-not-critical
    when: { not: { touches_critical: true } }
    action: warn
";
    let policy = parse_policy(yaml).unwrap();

    let non_critical = run_rules(&policy, &facts_with(false, false, 1));
    assert_eq!(decide(&non_critical), Action::Warn);

    let critical = run_rules(&policy, &facts_with(false, true, 1));
    assert_eq!(decide(&critical), Action::Pass);
}

#[test]
fn missing_evidence_uses_presence_semantics() {
    let yaml = "
schema_version: 1
rules:
  - id: need-sbom
    when: { missing_evidence: sbom }
    action: warn
";
    let policy = parse_policy(yaml).unwrap();

    let without = facts_with(true, false, 1);
    assert_eq!(decide(&run_rules(&policy, &without)), Action::Warn);

    let mut with = facts_with(true, false, 1);
    use aegis_policy::EvidenceKind;
    with.available_evidence.insert(EvidenceKind::Sbom);
    assert_eq!(decide(&run_rules(&policy, &with)), Action::Pass);
}

#[test]
fn risk_at_least_is_inclusive_boundary() {
    let yaml = "
schema_version: 1
rules:
  - id: gate
    when: { risk_at_least: 80 }
    action: block
";
    let policy = parse_policy(yaml).unwrap();

    assert_eq!(
        decide(&run_rules(&policy, &facts_with(true, true, 80))),
        Action::Block
    );
    assert_eq!(
        decide(&run_rules(&policy, &facts_with(true, true, 79))),
        Action::Pass
    );
}

#[test]
fn invalid_policies_are_rejected_with_clear_errors() {
    assert!(parse_policy("schema_version: 2").is_err());

    let bad_thresholds = "
schema_version: 1
thresholds: { warn_at: 90, high_at: 40, block_at: 80 }
";
    assert!(parse_policy(bad_thresholds).is_err());

    let duplicate_ids = "
schema_version: 1
rules:
  - id: dup
    when: { is_added: true }
    action: warn
  - id: dup
    when: { is_added: true }
    action: block
";
    assert!(parse_policy(duplicate_ids).is_err());

    let unknown_field = "
schema_version: 1
totally_unknown_section: 42
";
    assert!(parse_policy(unknown_field).is_err());
}
