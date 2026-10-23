import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# ----------------------------------------------------------------------
# SUPERVISED THREAT CLASSIFIER MODEL
# Full synthetic corpus: 10,000+ samples
# Split: 80% training / 20% testing (stratified)
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

# Features: [Total IOCs, Public IPs, LOLBAS Cmds, YARA Hits,
#            Shadow Copies Wiped, Mimikatz Hits, WebShell Hits, Entropy x10]


def _generate_synthetic_dataset(n_samples=10000, random_state=42):
    """
    Generate a balanced synthetic ground-truth dataset (>= 10,000 samples)
    for the multi-class threat classifier used by the Cyber Triage Tool.
    """
    rng = np.random.default_rng(random_state)
    samples_per_class = n_samples // 5
    remainder = n_samples - samples_per_class * 5

    X_list = []
    y_list = []

    # Class 0 – Benign / Normal Activity
    n0 = samples_per_class + remainder
    X0 = np.column_stack([
        rng.integers(0, 4, n0),
        rng.integers(0, 2, n0),
        rng.integers(0, 1, n0),
        rng.integers(0, 1, n0),
        np.zeros(n0, dtype=int),
        np.zeros(n0, dtype=int),
        np.zeros(n0, dtype=int),
        rng.integers(35, 55, n0),
    ])
    X_list.append(X0)
    y_list.append(np.zeros(n0, dtype=int))

    # Class 1 – Ransomware / Extortion
    n1 = samples_per_class
    X1 = np.column_stack([
        rng.integers(5, 18, n1),
        rng.integers(1, 6, n1),
        rng.integers(1, 5, n1),
        rng.integers(1, 5, n1),
        rng.integers(0, 2, n1),
        np.zeros(n1, dtype=int),
        np.zeros(n1, dtype=int),
        rng.integers(70, 85, n1),
    ])
    X1[:, 4] = rng.choice([0, 1], size=n1, p=[0.25, 0.75])
    X_list.append(X1)
    y_list.append(np.ones(n1, dtype=int))

    # Class 2 – APT & C2 Communication
    n2 = samples_per_class
    X2 = np.column_stack([
        rng.integers(4, 16, n2),
        rng.integers(2, 8, n2),
        rng.integers(0, 4, n2),
        rng.integers(0, 4, n2),
        np.zeros(n2, dtype=int),
        np.zeros(n2, dtype=int),
        np.zeros(n2, dtype=int),
        rng.integers(60, 78, n2),
    ])
    X_list.append(X2)
    y_list.append(np.full(n2, 2, dtype=int))

    # Class 3 – Credential Theft & Access
    n3 = samples_per_class
    X3 = np.column_stack([
        rng.integers(2, 12, n3),
        rng.integers(0, 4, n3),
        rng.integers(1, 5, n3),
        rng.integers(0, 4, n3),
        np.zeros(n3, dtype=int),
        rng.integers(0, 2, n3),
        np.zeros(n3, dtype=int),
        rng.integers(55, 72, n3),
    ])
    X3[:, 5] = rng.choice([0, 1], size=n3, p=[0.2, 0.8])
    X_list.append(X3)
    y_list.append(np.full(n3, 3, dtype=int))

    # Class 4 – Web Application Compromise
    n4 = samples_per_class
    X4 = np.column_stack([
        rng.integers(3, 14, n4),
        rng.integers(1, 6, n4),
        rng.integers(0, 3, n4),
        rng.integers(0, 4, n4),
        np.zeros(n4, dtype=int),
        np.zeros(n4, dtype=int),
        rng.integers(0, 2, n4),
        rng.integers(52, 70, n4),
    ])
    X4[:, 6] = rng.choice([0, 1], size=n4, p=[0.2, 0.8])
    X_list.append(X4)
    y_list.append(np.full(n4, 4, dtype=int))

    X = np.vstack(X_list).astype(np.float64)
    y = np.concatenate(y_list)

    idx = rng.permutation(len(y))
    return X[idx], y[idx]


# ----------------------------------------------------------------------
# Build full corpus (>= 10,000 samples) then 80/20 stratified split
# ----------------------------------------------------------------------
X_FULL, Y_FULL = _generate_synthetic_dataset(n_samples=10000, random_state=42)
assert len(X_FULL) >= 10000, "Full dataset must contain at least 10,000 samples"

X_TRAIN, X_TEST, Y_TRAIN, Y_TEST = train_test_split(
    X_FULL,
    Y_FULL,
    test_size=0.20,          # 20% hold-out for testing
    train_size=0.80,         # 80% for training
    random_state=42,
    stratify=Y_FULL          # preserve class balance in both splits
)

FULL_DATASET_SIZE = len(X_FULL)
TRAIN_SIZE = len(X_TRAIN)
TEST_SIZE = len(X_TEST)

# Train Random Forest only on the 80% training split
rf_model = RandomForestClassifier(
    n_estimators=150,
    max_depth=12,
    min_samples_leaf=4,
    random_state=42,
    n_jobs=-1
)
rf_model.fit(X_TRAIN, Y_TRAIN)

# Evaluate on the held-out 20% test set
_y_pred_test = rf_model.predict(X_TEST)
TEST_ACCURACY = float(accuracy_score(Y_TEST, _y_pred_test))
TEST_CLASS_REPORT = classification_report(
    Y_TEST,
    _y_pred_test,
    target_names=[LABELS_MAP[i] for i in range(5)],
    output_dict=True,
    zero_division=0
)
TEST_CONFUSION = confusion_matrix(Y_TEST, _y_pred_test).tolist()

CLASS_COUNTS_TRAIN = {LABELS_MAP[i]: int(np.sum(Y_TRAIN == i)) for i in range(5)}
CLASS_COUNTS_TEST = {LABELS_MAP[i]: int(np.sum(Y_TEST == i)) for i in range(5)}
CLASS_COUNTS_FULL = {LABELS_MAP[i]: int(np.sum(Y_FULL == i)) for i in range(5)}

# Backward-compatible aliases used by older code / UI
DATASET_SIZE = TRAIN_SIZE
CLASS_COUNTS = CLASS_COUNTS_TRAIN


def get_dataset_metrics():
    """Return summary of the 80/20 train–test split and test-set performance."""
    return {
        "full_dataset_size": FULL_DATASET_SIZE,
        "train_size": TRAIN_SIZE,
        "test_size": TEST_SIZE,
        "train_ratio": 0.80,
        "test_ratio": 0.20,
        "test_accuracy_pct": round(TEST_ACCURACY * 100, 2),
        "class_counts_full": CLASS_COUNTS_FULL,
        "class_counts_train": CLASS_COUNTS_TRAIN,
        "class_counts_test": CLASS_COUNTS_TEST,
        "test_confusion_matrix": TEST_CONFUSION,
    }


def predict_supervised_threat(features):
    """
    Predicts threat vector probability distribution using the Random Forest
    model trained on the 80% training split (8,000 samples).
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

    feature_names = [
        "Total IOCs", "Public IPs", "LOLBAS Commands", "YARA Hits",
        "Shadow Wiping", "Mimikatz Activity", "WebShell Activity", "Entropy"
    ]
    importances = rf_model.feature_importances_
    top_features = [
        {"feature": f, "importance": round(float(imp) * 100, 1)}
        for f, imp in sorted(zip(feature_names, importances), key=lambda x: -x[1])[:4]
    ]

    return {
        "predicted_threat": primary_label,
        "confidence_pct": confidence,
        "probability_breakdown": prob_dict,
        "top_features": top_features,
        "training_samples": TRAIN_SIZE,
        "test_samples": TEST_SIZE,
        "full_dataset_size": FULL_DATASET_SIZE,
        "train_test_split": "80/20",
        "test_accuracy_pct": round(TEST_ACCURACY * 100, 2),
        "class_distribution": CLASS_COUNTS_TRAIN,
    }
