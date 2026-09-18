import numpy as np
from sklearn.ensemble import IsolationForest

# ----------------------------------------------------------------------
# Baseline Multi-Dimensional Training Dataset
# Features:
# [Total IOCs, Public IPs, YARA Hits, LOLBAS Cmds, Keywords, Entropy (scaled x10), MITRE Count]
# ----------------------------------------------------------------------
BENIGN_PROFILES = [
    [0, 0, 0, 0, 0, 45, 0],
    [1, 0, 0, 0, 0, 48, 0],
    [2, 0, 0, 0, 1, 52, 0],
    [0, 0, 0, 0, 0, 38, 0],
    [3, 1, 0, 0, 0, 50, 0],
    [1, 1, 0, 0, 0, 42, 0],
    [2, 0, 0, 0, 0, 49, 0],
    [0, 0, 0, 0, 1, 40, 0],
    [4, 1, 0, 0, 1, 51, 0],
    [1, 0, 0, 0, 0, 46, 0]
]

ATTACK_PROFILES = [
    [8, 3, 2, 2, 6, 75, 4],
    [12, 5, 3, 3, 9, 78, 6],
    [6, 2, 2, 1, 4, 72, 3],
    [15, 6, 4, 4, 12, 79, 7],
    [5, 3, 1, 2, 5, 68, 3],
    [10, 4, 3, 2, 8, 76, 5],
    [20, 8, 5, 6, 15, 80, 8]
]

# Initialize and train Isolation Forest model
TRAINING_SET = np.array(BENIGN_PROFILES + ATTACK_PROFILES)
model = IsolationForest(
    n_estimators=100,
    contamination=0.35,
    random_state=42
)
model.fit(TRAINING_SET)

def detect_anomalies(features_dict):
    """
    Evaluates forensic feature vector against AI Isolation Forest model.
    features_dict should contain:
    - total_iocs
    - public_ips
    - yara_hits
    - lolbas_cmds
    - keywords_count
    - entropy (0-8)
    - mitre_count
    """
    feature_vector = np.array([[
        features_dict.get("total_iocs", 0),
        features_dict.get("public_ips", 0),
        features_dict.get("yara_hits", 0),
        features_dict.get("lolbas_cmds", 0),
        features_dict.get("keywords_count", 0),
        int(features_dict.get("entropy", 5.0) * 10),
        features_dict.get("mitre_count", 0)
    ]])

    prediction = model.predict(feature_vector)[0]
    decision_score = model.decision_function(feature_vector)[0]

    # Normalize decision score to a 0.0 - 100.0 Anomaly Index
    # decision_score is typically between -0.3 (anomaly) and +0.3 (normal)
    normalized_score = max(0.0, min(100.0, (0.35 - decision_score) * 140.0))

    is_anomaly = bool(prediction == -1 or normalized_score > 60.0)

    if normalized_score >= 75.0:
        confidence = "High Confidence Anomaly"
        status = "Highly Anomalous"
    elif normalized_score >= 50.0:
        confidence = "Medium Confidence Anomaly"
        status = "Anomalous"
    else:
        confidence = "Normal Baseline"
        status = "Normal"

    return {
        "is_anomaly": is_anomaly,
        "status": status,
        "anomaly_score": round(float(normalized_score), 2),
        "raw_decision_score": round(float(decision_score), 4),
        "confidence": confidence,
        "evaluated_features": {
            "Total IOCs": features_dict.get("total_iocs", 0),
            "Public IPs": features_dict.get("public_ips", 0),
            "YARA Signature Hits": features_dict.get("yara_hits", 0),
            "LOLBAS / Obfuscated Commands": features_dict.get("lolbas_cmds", 0),
            "Threat Keywords": features_dict.get("keywords_count", 0),
            "MITRE ATT&CK Techniques": features_dict.get("mitre_count", 0)
        }
    }
