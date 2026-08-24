use serde::Serialize;

pub const RISK_FORMULA_VERSION: &str = "risk-formula/v1";

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct ScoreComponents {
    pub magnitude: f64,
    pub impact_breadth: f64,
    pub proximity: f64,
    pub critical: f64,
    pub evidence_gap: f64,
    pub findings: f64,
}

const WEIGHT_MAGNITUDE: f64 = 0.18;
const WEIGHT_IMPACT: f64 = 0.20;
const WEIGHT_PROXIMITY: f64 = 0.12;
const WEIGHT_CRITICAL: f64 = 0.20;
const WEIGHT_EVIDENCE_GAP: f64 = 0.20;
const WEIGHT_FINDINGS: f64 = 0.10;

pub fn compute_score(components: &ScoreComponents) -> u8 {
    let raw = WEIGHT_MAGNITUDE * components.magnitude
        + WEIGHT_IMPACT * components.impact_breadth
        + WEIGHT_PROXIMITY * components.proximity
        + WEIGHT_CRITICAL * components.critical
        + WEIGHT_EVIDENCE_GAP * components.evidence_gap
        + WEIGHT_FINDINGS * components.findings;

    let clamped = raw.clamp(0.0, 1.0);
    (100.0 * clamped).round().min(100.0) as u8
}

pub fn score_level(score: u8, thresholds: &crate::rules::Thresholds) -> &'static str {
    if score >= thresholds.block_at {
        "critical"
    } else if score >= thresholds.high_at {
        "high"
    } else if score >= thresholds.warn_at {
        "medium"
    } else {
        "low"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_prd_example_scores_49() {
        let components = ScoreComponents {
            magnitude: 0.40,
            impact_breadth: 0.40,
            proximity: (1.0 / 3.0 + 1.0 / 4.0) / 2.0,
            critical: 1.0,
            evidence_gap: 0.50,
            findings: 0.0,
        };

        assert_eq!(compute_score(&components), 49);
    }

    #[test]
    fn zero_components_score_zero_and_max_score_hundred() {
        let zero = ScoreComponents {
            magnitude: 0.0,
            impact_breadth: 0.0,
            proximity: 0.0,
            critical: 0.0,
            evidence_gap: 0.0,
            findings: 0.0,
        };
        assert_eq!(compute_score(&zero), 0);

        let max = ScoreComponents {
            magnitude: 1.0,
            impact_breadth: 1.0,
            proximity: 1.0,
            critical: 1.0,
            evidence_gap: 1.0,
            findings: 1.0,
        };
        assert_eq!(compute_score(&max), 100);
    }

    #[test]
    fn out_of_range_components_are_clamped() {
        let over = ScoreComponents {
            magnitude: 5.0,
            impact_breadth: -3.0,
            proximity: 2.0,
            critical: 1.0,
            evidence_gap: 0.5,
            findings: 0.0,
        };
        let score = compute_score(&over);
        assert!(score <= 100);
    }

    #[test]
    fn score_is_monotonic_per_component() {
        let steps = [0.0, 0.25, 0.5, 0.75, 1.0];
        for magnitude in steps {
            for impact in steps {
                for proximity in steps {
                    let base = ScoreComponents {
                        magnitude,
                        impact_breadth: impact,
                        proximity,
                        critical: 0.5,
                        evidence_gap: 0.25,
                        findings: 0.0,
                    };
                    let mut bumped = base;
                    bumped.findings += 0.25;
                    assert!(compute_score(&bumped) >= compute_score(&base));
                }
            }
        }
    }

    #[test]
    fn levels_follow_thresholds() {
        use crate::rules::Thresholds;
        let t = Thresholds::default();
        assert_eq!(score_level(10, &t), "low");
        assert_eq!(score_level(45, &t), "medium");
        assert_eq!(score_level(70, &t), "high");
        assert_eq!(score_level(95, &t), "critical");
    }
}
