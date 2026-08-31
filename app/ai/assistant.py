import re
from typing import Dict, Any, List
from app.ai.rag import retrieve_mitre_context

def sanitize_untrusted_input(text: str) -> str:
    """
    Prompt injection defense: Neutralizes instructions inside scanned content.
    """
    if not text:
        return ""
    # Strip potential instruction overrides
    sanitized = re.sub(r"(ignore\s+all\s+previous\s+instructions|system\s+override|you\s+are\s+now|system\s+prompt)", "[FILTERED_OVERRIDE_TOKEN]", text, flags=re.IGNORECASE)
    return sanitized[:500]

def generate_grounded_ai_analysis(
    target: str,
    scan_type: str,
    verdict: str,
    risk_score: int,
    indicators: List[Dict[str, Any]],
    ml_analysis: Dict[str, Any],
    anomaly_analysis: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Produces strictly grounded natural-language threat summary and actionable SOC recommendations.
    Never invents IOCs or evidence not present in indicators.
    """
    mitre_tactics = retrieve_mitre_context(indicators)
    
    key_findings = []
    for ind in indicators:
        key_findings.append(f"[{ind.get('severity')}] {ind.get('name')}: {ind.get('description')}")

    ml_prediction = ml_analysis.get("prediction", "BENIGN")
    ml_prob = ml_analysis.get("probability", 0.0)
    anomaly_status = anomaly_analysis.get("status", "NORMAL_DISTRIBUTION")
    anomaly_score = anomaly_analysis.get("anomalyScore", 0.0)

    if verdict in ["CRITICAL", "HIGH_RISK"]:
        summary = (
            f"Target '{sanitize_untrusted_input(target)}' represents a confirmed {verdict} threat vector (Score: {risk_score}/100). "
            f"The Supervised ML classifier evaluated a {int(ml_prob * 100)}% {ml_prediction} probability with {len(indicators)} corroborating micro-indicators. "
            f"Anomaly detection rated sample deviation at {int(anomaly_score * 100)}% ({anomaly_status})."
        )
        recommendations = [
            "Quarantine and block this asset immediately across edge firewalls and endpoint agents.",
            "Add extracted IP addresses and domain IOCs to egress blocklists.",
            "Escalate incident ticket to Tier-2 SOC response team for scope assessment.",
        ]
    elif verdict == "SUSPICIOUS":
        summary = (
            f"Target '{sanitize_untrusted_input(target)}' exhibits suspicious characteristics (Score: {risk_score}/100) with "
            f"{len(indicators)} minor indicator signals and an anomaly rating of {int(anomaly_score * 100)}%."
        )
        recommendations = [
            "Isolate the asset in a dynamic sandbox environment before execution.",
            "Monitor outbound network connections for unexpected telemetry beacons.",
        ]
    elif verdict == "REQUIRES_REVIEW":
        summary = (
            f"Target '{sanitize_untrusted_input(target)}' exhibits anomalous structural deviation ({int(anomaly_score * 100)}% anomaly score) "
            "despite lacking known malicious signatures. Manual inspection recommended for zero-day identification."
        )
        recommendations = [
            "Perform manual reverse engineering and entropy section inspection.",
            "Inspect newly registered domain parameters or unexpected API imports.",
        ]
    else:
        summary = f"Target '{sanitize_untrusted_input(target)}' passed all rule-based and ML classifier checks (Score: {risk_score}/100, Clean/Safe)."
        recommendations = [
            "No defensive quarantine or blocking action required.",
            "Maintain standard continuous monitoring telemetry.",
        ]

    return {
        "summary": summary,
        "keyFindings": key_findings,
        "mitreTactics": mitre_tactics,
        "recommendations": recommendations,
        "grounded": True,
    }
