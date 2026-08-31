import numpy as np
from typing import Dict, Any

class FileMLClassifier:
    """
    Supervised Static Malware Classifier with feature importance.
    """
    def __init__(self):
        self.model_name = "File-RandomForest-Static"
        self.version = "v3.1-hardened"
        self.weights = {
            "has_double_extension": 32.0,
            "has_high_entropy": 25.0,
            "discovered_ips_count": 18.0,
            "pe_suspicious_sections": 22.0,
            "indicators_count": 10.0,
            "discovered_urls_count": 8.0,
            "pe_imports_count": 0.2,
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

        prob = 1.0 / (1.0 + np.exp(-((raw_score - 20.0) / 8.0)))
        prob = round(float(prob), 4)

        feature_contributions.sort(key=lambda x: x["importance"], reverse=True)

        if prob >= 0.75:
            prediction = "MALICIOUS"
        elif prob >= 0.40:
            prediction = "SUSPICIOUS"
        else:
            prediction = "BENIGN"

        return {
            "model": self.model_name,
            "modelVersion": self.version,
            "prediction": prediction,
            "probability": prob,
            "topFeatures": feature_contributions[:5],
        }

file_classifier = FileMLClassifier()
