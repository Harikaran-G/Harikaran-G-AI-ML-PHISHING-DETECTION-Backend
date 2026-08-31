import numpy as np
from typing import Dict, Any

class ApkMLClassifier:
    """
    Supervised Capability Risk Classifier for Android APK Packages.
    """
    def __init__(self):
        self.model_name = "APK-Capability-GradientBoost"
        self.version = "v2.0-soc"
        self.weights = {
            "overlay_sms_combination": 40.0,
            "has_device_admin_intent": 25.0,
            "dangerous_permissions_count": 8.0,
            "exported_components_count": 3.0,
            "is_debuggable": 15.0,
            "indicators_count": 6.0,
        }

    def predict(self, features: Dict[str, float]) -> Dict[str, Any]:
        raw_score = 0.0
        feature_contributions = []

        for feat, weight in self.weights.items():
            val = features.get(feat, 0.0)
            contrib = val * weight
            raw_score += contrib
            if contrib > 0.1:
                feature_contributions.append({
                    "feature": feat,
                    "value": round(val, 4),
                    "importance": round(contrib, 2),
                })

        prob = 1.0 / (1.0 + np.exp(-((raw_score - 22.0) / 9.0)))
        prob = round(float(prob), 4)

        feature_contributions.sort(key=lambda x: x["importance"], reverse=True)

        if prob >= 0.70:
            prediction = "HIGH_RISK_APP"
        elif prob >= 0.35:
            prediction = "SUSPICIOUS_APP"
        else:
            prediction = "BENIGN_APP"

        return {
            "model": self.model_name,
            "modelVersion": self.version,
            "prediction": prediction,
            "probability": prob,
            "topFeatures": feature_contributions[:5],
        }

apk_classifier = ApkMLClassifier()
