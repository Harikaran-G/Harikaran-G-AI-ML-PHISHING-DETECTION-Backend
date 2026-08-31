import math
import re
from typing import List, Dict, Any, Tuple

def calculate_risk_score(indicators: List[Dict[str, Any]]) -> Tuple[int, str, float, List[str]]:
    """
    Computes a normalized risk score (0-100), verdict, confidence, and explainable rationale
    based on individual detected indicators.
    
    Score brackets:
      0–29   SAFE
      30–59  SUSPICIOUS
      60–79  HIGH RISK
      80–100 CRITICAL
    """
    if not indicators:
        return 0, "SAFE", 0.95, ["Target passed all static inspection checks without triggering threat heuristics."]

    total_weight = 0.0
    weighted_confidence = 0.0
    critical_count = 0
    high_count = 0
    
    severity_multipliers = {
        "CRITICAL": 1.5,
        "HIGH": 1.2,
        "MEDIUM": 1.0,
        "LOW": 0.6,
        "INFO": 0.2
    }

    explanations: List[str] = []

    for ind in indicators:
        severity = ind.get("severity", "MEDIUM")
        confidence = float(ind.get("confidence", 0.8))
        base_score = float(ind.get("score", 15))
        mult = severity_multipliers.get(severity, 1.0)
        
        contribution = base_score * mult * confidence
        total_weight += contribution
        weighted_confidence += confidence
        
        if severity == "CRITICAL":
            critical_count += 1
        elif severity == "HIGH":
            high_count += 1
            
        explanations.append(f"[{severity}] {ind.get('name')}: {ind.get('description')}")

    # Correlated escalation
    if critical_count >= 2:
        total_weight += 20
    elif critical_count == 1 and high_count >= 1:
        total_weight += 15
    elif high_count >= 3:
        total_weight += 12

    # Normalized capping
    final_score = int(min(100, max(0, round(total_weight))))
    avg_confidence = round(weighted_confidence / len(indicators), 2)

    # Verdict assignment
    if final_score >= 80 or critical_count >= 2:
        verdict = "CRITICAL"
        final_score = max(final_score, 80)
    elif final_score >= 60 or critical_count == 1:
        verdict = "HIGH_RISK"
        final_score = max(final_score, 60)
    elif final_score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return final_score, verdict, avg_confidence, explanations
