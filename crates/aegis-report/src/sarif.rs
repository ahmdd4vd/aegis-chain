use aegis_core::decision::DecisionReport;
use aegis_policy::Action;
use serde_json::{json, Value};

fn sarif_level(status: Action) -> &'static str {
    match status {
        Action::Block => "error",
        Action::Warn => "warning",
        Action::Pass => "note",
    }
}

pub fn render(report: &DecisionReport) -> String {
    let mut rules: Vec<Value> = Vec::new();
    let mut rule_ids: Vec<String> = Vec::new();

    for decision in &report.decisions {
        for trace in &decision.traces {
            if trace.matched && !rule_ids.contains(&trace.rule_id) {
                rule_ids.push(trace.rule_id.clone());
                let mut rule = json!({
                    "id": trace.rule_id,
                    "shortDescription": { "text": trace
                        .message
                        .clone()
                        .unwrap_or_else(|| format!("Policy rule {}", trace.rule_id)) }
                });
                if let Some(message) = &trace.message {
                    rule["fullDescription"] = json!({ "text": message });
                }
                rules.push(rule);
            }
        }
    }

    let results: Vec<Value> = report
        .decisions
        .iter()
        .filter(|decision| decision.status != Action::Pass)
        .map(|decision| {
            let mut text = format!(
                "{} ({}) risk {}/100 ({}), status {}",
                decision.change.name,
                decision.change.kind.label(),
                decision.score,
                decision.level,
                decision.status.label().to_uppercase()
            );
            if !decision.matched_rules.is_empty() {
                text.push_str(&format!(
                    ", matched: {}",
                    decision.matched_rules.join(", ")
                ));
            }

            json!({
                "ruleId": decision.matched_rules.first().cloned().unwrap_or_else(|| "aegis-risk".to_string()),
                "level": sarif_level(decision.status),
                "message": { "text": text },
                "properties": {
                    "package": decision.change.name,
                    "riskScore": decision.score,
                    "riskLevel": decision.level,
                    "impactedRoots": decision.change.impacted_roots.iter().map(|root| root.name.clone()).collect::<Vec<_>>(),
                }
            })
        })
        .collect();

    let sarif = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "aegis-chain",
                    "informationUri": "https://github.com/ahmdd4vd/aegis-chain",
                    "rules": rules
                }
            },
            "results": results
        }]
    });

    serde_json::to_string_pretty(&sarif).expect("SARIF serializes to JSON")
}

pub fn validate_shape(sarif: &str) -> Result<(), String> {
    let value: Value =
        serde_json::from_str(sarif).map_err(|error| format!("invalid JSON: {error}"))?;
    if value["version"] != "2.1.0" {
        return Err("sarif version must be 2.1.0".to_string());
    }
    let runs = value["runs"]
        .as_array()
        .ok_or_else(|| "runs must be an array".to_string())?;
    if runs.len() != 1 {
        return Err("expected exactly one run".to_string());
    }
    let driver_name = runs[0]["tool"]["driver"]["name"]
        .as_str()
        .ok_or_else(|| "tool.driver.name missing".to_string())?;
    if driver_name != "aegis-chain" {
        return Err(format!("unexpected driver name {driver_name}"));
    }
    for result in runs[0]["results"].as_array().unwrap_or(&Vec::new()) {
        if result["ruleId"].as_str().is_none() {
            return Err("result.ruleId missing".to_string());
        }
        if result["level"].as_str().is_none() {
            return Err("result.level missing".to_string());
        }
        if result["message"]["text"].as_str().is_none() {
            return Err("result.message.text missing".to_string());
        }
    }
    Ok(())
}
