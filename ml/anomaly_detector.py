import numpy as np
from sklearn.ensemble import IsolationForest

# ----------------------------------------------------------------------
# Isolation Forest Anomaly Detector
# Full synthetic corpus: 10,000+ samples
# Split: 80% training / 20% testing
# Features:
# [Total IOCs, Public IPs, YARA Hits, LOLBAS Cmds, Keywords, Entropy (x10), MITRE Count]
# ----------------------------------------------------------------------


def _generate_anomaly_training_set(n_samples=10000, random_state=42):
    """Generate large mixed benign + attack feature matrix for Isolation Forest."""
    rng = np.random.default_rng(random_state)
    n_benign = int(n_samples * 0.65)
    n_attack = n_samples - n_benign

    benign = np.column_stack([
        rng.integers(0, 4, n_benign),
        rng.integers(0, 2, n_benign),
        rng.integers(0, 1, n_benign),
        rng.integers(0, 1, n_benign),
        rng.integers(0, 3, n_benign),
        rng.integers(35, 55, n_benign),
        rng.integers(0, 2, n_benign),
    ])

    attack = np.column_stack([
        rng.integers(5, 22, n_attack),
        rng.integers(2, 9, n_attack),
        rng.integers(1, 6, n_attack),
        rng.integers(1, 6, n_attack),
        rng.integers(3, 16, n_attack),
        rng.integers(65, 85, n_attack),
        rng.integers(2, 10, n_attack),
    ])

    # Labels for evaluation: 1 = benign (inlier), -1 = attack (outlier)
    y_benign = np.ones(n_benign, dtype=int)
    y_attack = -np.ones(n_attack, dtype=int)

    data = np.vstack([benign, attack]).astype(np.float64)
    labels = np.concatenate([y_benign, y_attack])

    idx = rng.permutation(len(labels))
    return data[idx], labels[idx]


X_FULL, Y_FULL = _generate_anomaly_training_set(n_samples=10000, random_state=42)
assert len(X_FULL) >= 10000

# 80% train / 20% test split (no stratify needed for unsupervised fit,
# but we keep labels only for evaluation on the hold-out set)
rng = np.random.default_rng(42)
n = len(X_FULL)
perm = rng.permutation(n)
split = int(n * 0.80)
train_idx, test_idx = perm[:split], perm[split:]

X_TRAIN = X_FULL[train_idx]
X_TEST = X_FULL[test_idx]
Y_TEST = Y_FULL[test_idx]

FULL_DATASET_SIZE = len(X_FULL)
TRAIN_SIZE = len(X_TRAIN)
TEST_SIZE = len(X_TEST)

model = IsolationForest(
    n_estimators=150,
    contamination=0.35,
    random_state=42,
    n_jobs=-1
)
model.fit(X_TRAIN)  # fit only on 80% training data

# Evaluate on held-out 20%
_y_pred_test = model.predict(X_TEST)
# IsolationForest: -1 = anomaly, 1 = normal; same encoding as Y_TEST
TEST_ACCURACY = float(np.mean(_y_pred_test == Y_TEST))

ANOMALY_DATASET_SIZE = TRAIN_SIZE


def get_anomaly_dataset_metrics():
    return {
        "full_dataset_size": FULL_DATASET_SIZE,
        "train_size": TRAIN_SIZE,
        "test_size": TEST_SIZE,
        "train_ratio": 0.80,
        "test_ratio": 0.20,
        "test_accuracy_pct": round(TEST_ACCURACY * 100, 2),
    }


def detect_anomalies(features_dict):
    """
    Evaluates forensic feature vector against Isolation Forest trained on
    the 80% training split (8,000 samples).
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
        "training_samples": TRAIN_SIZE,
        "test_samples": TEST_SIZE,
        "full_dataset_size": FULL_DATASET_SIZE,
        "train_test_split": "80/20",
        "test_accuracy_pct": round(TEST_ACCURACY * 100, 2),
        "evaluated_features": {
            "Total IOCs": features_dict.get("total_iocs", 0),
            "Public IPs": features_dict.get("public_ips", 0),
            "YARA Signature Hits": features_dict.get("yara_hits", 0),
            "LOLBAS / Obfuscated Commands": features_dict.get("lolbas_cmds", 0),
            "Threat Keywords": features_dict.get("keywords_count", 0),
            "MITRE ATT&CK Techniques": features_dict.get("mitre_count", 0)
        }
    }
