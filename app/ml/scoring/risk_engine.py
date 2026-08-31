from typing import Dict, Any, List

def calculate_unified_risk(
    rule_score: int,
    ml_analysis: Dict[str, Any],
    anomaly_analysis: Dict[str, Any],
    indicators: List[Dict[str, Any]],
    correlations_count: int = 0,
) -> Dict[str, Any]:
    """
    Deterministic multi-vector risk engine combining:
    - Rule-based score (0–100)
    - Supervised ML probability (0.0–1.0)
    - Isolation Forest Anomaly score (0.0–1.0)
    - IOC Correlation multipliers
    """
    ml_prob = ml_analysis.get("probability", 0.0)
    anomaly_score = anomaly_analysis.get("anomalyScore", 0.0)

    # Weighted Aggregation:
    # 50% Deterministic Rule Engine + 30% Supervised ML + 20% Unsupervised Anomaly
    base_score = (rule_score * 0.50) + (ml_prob * 100.0 * 0.30) + (anomaly_score * 100.0 * 0.20)

    # Correlation boost if cross-vector IOC links exist
    if correlations_count > 0:
        base_score += min(15.0, correlations_count * 5.0)

    # Critical Indicator override
    has_critical_indicator = any(i.get("severity") == "CRITICAL" for i in indicators)
    if has_critical_indicator and base_score < 70:
        base_score = 75.0

    final_score = int(round(min(100.0, max(0.0, base_score))))

    # Verdict derivation
    if final_score >= 80:
        verdict = "CRITICAL"
    elif final_score >= 60:
        verdict = "HIGH_RISK"
    elif final_score >= 30:
        verdict = "SUSPICIOUS"
    elif anomaly_score >= 0.70 and final_score < 30:
        verdict = "REQUIRES_REVIEW"
    else:
        verdict = "SAFE"

    confidence = round(0.80 + (ml_prob * 0.10) + (0.08 if len(indicators) > 0 else 0.0), 2)
    confidence = min(0.99, max(0.70, confidence))

    return {
        "riskScore": final_score,
        "verdict": verdict,
        "confidence": confidence,
        "signals": {
            "ruleScoreWeight": round(rule_score * 0.50, 1),
            "mlScoreWeight": round(ml_prob * 100.0 * 0.30, 1),
            "anomalyScoreWeight": round(anomaly_score * 100.0 * 0.20, 1),
        }
    }
