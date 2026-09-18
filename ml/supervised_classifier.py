import numpy as np
from sklearn.ensemble import RandomForestClassifier

# ----------------------------------------------------------------------
# SUPERVISED THREAT CLASSIFIER MODEL
# Classes:
# 0: Benign / Normal Activity
# 1: Ransomware / Destruction
# 2: APT & C2 Beaconing
# 3: Credential Theft & Access
# 4: Web Application Exploitation
# ----------------------------------------------------------------------

LABELS_MAP = {
    0: "Benign / Normal Activity",
    1: "Ransomware / Extortion",
    2: "APT & C2 Communication",
    3: "Credential Theft & Access",
    4: "Web Application Compromise"
}

# Synthetic Ground Truth Training Data Matrix
# Features: [Total IOCs, Public IPs, LOLBAS Cmds, YARA Hits, Shadow Copies Wiped, Mimikatz Hits, WebShell Hits, Entropy x10]
X_TRAIN = np.array([
    # Benign
    [0, 0, 0, 0, 0, 0, 0, 42],
    [1, 0, 0, 0, 0, 0, 0, 45],
    [2, 1, 0, 0, 0, 0, 0, 50],
    [1, 0, 0, 0, 0, 0, 0, 39],
    # Ransomware
    [6, 2, 2, 2, 1, 0, 0, 78],
    [10, 3, 3, 3, 1, 0, 0, 79],
    [8, 2, 2, 2, 1, 0, 0, 75],
    # APT & C2
    [5, 3, 1, 1, 0, 0, 0, 65],
    [7, 4, 2, 2, 0, 0, 0, 68],
    [12, 5, 2, 2, 0, 0, 0, 70],
    # Credential Theft
    [3, 1, 2, 1, 0, 1, 0, 62],
    [4, 1, 3, 2, 0, 1, 0, 64],
    [6, 2, 2, 2, 0, 1, 0, 66],
    # Web Exploitation
    [4, 2, 1, 1, 0, 0, 1, 58],
    [6, 3, 1, 2, 0, 0, 1, 60],
    [8, 4, 2, 2, 0, 0, 1, 63]
])

Y_TRAIN = np.array([0, 0, 0, 0, 1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 4])

# Train Random Forest Classifier
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_TRAIN, Y_TRAIN)

def predict_supervised_threat(features):
    """
    Predicts threat vector probability distribution using trained Random Forest model.
    """
    vec = np.array([[
        features.get("total_iocs", 0),
        features.get("public_ips", 0),
        features.get("lolbas_cmds", 0),
        features.get("yara_hits", 0),
        1 if features.get("has_shadow_wiping") else 0,
        1 if features.get("has_mimikatz") else 0,
        1 if features.get("has_webshell") else 0,
        int(features.get("entropy", 5.0) * 10)
    ]])

    pred_class = rf_model.predict(vec)[0]
    probabilities = rf_model.predict_proba(vec)[0]

    prob_dict = {}
    for idx, prob in enumerate(probabilities):
        label = LABELS_MAP.get(idx, f"Class {idx}")
        prob_dict[label] = round(float(prob) * 100, 1)

    primary_label = LABELS_MAP.get(pred_class, "Suspicious Activity")
    confidence = prob_dict.get(primary_label, 80.0)

    # Calculate Feature Importance contribution
    feature_names = ["Total IOCs", "Public IPs", "LOLBAS Commands", "YARA Hits", "Shadow Wiping", "Mimikatz Activity", "WebShell Activity", "Entropy"]
    importances = rf_model.feature_importances_
    top_features = [{"feature": f, "importance": round(float(imp) * 100, 1)} for f, imp in sorted(zip(feature_names, importances), key=lambda x: -x[1])[:4]]

    return {
        "predicted_threat": primary_label,
        "confidence_pct": confidence,
        "probability_breakdown": prob_dict,
        "top_features": top_features
    }
