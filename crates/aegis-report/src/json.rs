use aegis_core::decision::DecisionReport;

pub fn render(report: &DecisionReport) -> String {
    serde_json::to_string_pretty(report).expect("DecisionReport serializes to JSON")
}
