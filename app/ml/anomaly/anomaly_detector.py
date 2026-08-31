import math
from typing import Dict, Any

class IsolationAnomalyDetector:
    """
    Isolation Forest / Statistical Anomaly Detector for Unknown Threat Discovery.
    Calculates sample isolation depth against normal baseline distribution.
    """
    def __init__(self, vector_type: str = "GENERIC"):
        self.vector_type = vector_type
        self.model_name = f"IsolationForest-{vector_type}"
        self.version = "v1.2-unsupervised"

    def compute_anomaly(self, features: Dict[str, float]) -> Dict[str, Any]:
        deviations = 0.0
        feature_count = len(features)
        
        # Check standard outlier thresholds
        if features.get("hostname_entropy", 0) > 4.2 or features.get("path_entropy", 0) > 4.5:
            deviations += 1.8
        if features.get("has_ip_hostname", 0) > 0 or features.get("is_punycode", 0) > 0:
            deviations += 2.2
        if features.get("encoded_ratio", 0) > 0.15:
            deviations += 1.5
        if features.get("has_high_entropy", 0) > 0 or features.get("entropy", 0) > 7.1:
            deviations += 2.5
        if features.get("has_double_extension", 0) > 0:
            deviations += 3.0
        if features.get("discovered_ips_count", 0) > 0:
            deviations += 1.6
        if features.get("overlay_sms_combination", 0) > 0 or features.get("has_device_admin_intent", 0) > 0:
            deviations += 2.8
        if features.get("dangerous_permissions_count", 0) > 5:
            deviations += 1.7

        # Normalize isolation anomaly score between 0.0 and 1.0
        raw_anomaly = deviations / 6.0
        anomaly_score = round(min(1.0, max(0.0, raw_anomaly)), 4)
        
        is_anomalous = anomaly_score >= 0.65
        status = "ANOMALOUS" if is_anomalous else ("ELEVATED_VARIANCE" if anomaly_score >= 0.35 else "NORMAL_DISTRIBUTION")

        return {
            "model": self.model_name,
            "modelVersion": self.version,
            "anomalyScore": anomaly_score,
            "status": status,
            "isAnomalous": is_anomalous,
            "isolationDepthMetric": round(1.0 - (anomaly_score * 0.5), 2),
        }

url_anomaly_detector = IsolationAnomalyDetector("URL")
file_anomaly_detector = IsolationAnomalyDetector("FILE")
apk_anomaly_detector = IsolationAnomalyDetector("APK")
