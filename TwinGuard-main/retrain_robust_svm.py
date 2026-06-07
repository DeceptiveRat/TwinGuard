import random
import shutil
import time
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC


BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "evil_twin_detector.pkl"
SCALER_PATH = BASE_DIR / "feature_scaler.pkl"
RANDOM_SEED = 42


def tcp_sample(rng, rssi_range, rtt_range, new_bssid, is_attack, scenario):
    return {
        "Protocol": "TCP",
        "RSSI": round(rng.uniform(*rssi_range), 2),
        "RTT": round(rng.uniform(*rtt_range), 6),
        "new_BSSID": new_bssid,
        "is_attack": is_attack,
        "scenario": scenario,
    }


def udp_sample(rng, rssi_range, new_bssid, is_attack, scenario):
    return {
        "Protocol": "UDP",
        "RSSI": round(rng.uniform(*rssi_range), 2),
        "RTT": -1.0,
        "new_BSSID": new_bssid,
        "is_attack": is_attack,
        "scenario": scenario,
    }


def add_tcp(rows, rng, count, rssi_range, rtt_range, new_bssid, is_attack, scenario):
    for _ in range(count):
        rows.append(tcp_sample(rng, rssi_range, rtt_range, new_bssid, is_attack, scenario))


def add_udp(rows, rng, count, rssi_range, new_bssid, is_attack, scenario):
    for _ in range(count):
        rows.append(udp_sample(rng, rssi_range, new_bssid, is_attack, scenario))


def build_training_dataset(seed=RANDOM_SEED):
    rng = random.Random(seed)
    rows = []

    # Normal traffic: stable BSSID. Includes clear-good and weak-but-legitimate cases.
    add_tcp(rows, rng, 1200, (-68, -45), (0.0, 0.08), False, 0, "normal_clear_tcp")
    add_udp(rows, rng, 300, (-68, -45), False, 0, "normal_clear_udp")
    add_tcp(rows, rng, 1200, (-82, -70), (0.08, 0.2), False, 0, "normal_weak_tcp")
    add_udp(rows, rng, 300, (-82, -70), False, 0, "normal_weak_udp")

    # Evil Twin: BSSID changed. This remains a strong signal.
    add_tcp(rows, rng, 1200, (-95, -65), (0.1, 1.2), True, 1, "attack_new_bssid_tcp")
    add_udp(rows, rng, 300, (-95, -65), True, 1, "attack_new_bssid_udp")

    # Evil Twin-like anomaly without BSSID change: severe RSSI/RTT anomaly.
    # This teaches the model not to rely only on new_BSSID.
    add_tcp(rows, rng, 900, (-100, -85), (0.35, 1.5), False, 1, "attack_no_new_bssid_tcp")
    add_udp(rows, rng, 300, (-100, -85), False, 1, "attack_no_new_bssid_udp")

    # Boundary anomaly without BSSID change: not as obvious as the clear attack,
    # but RSSI/RTT together are worse than the normal-weak range.
    add_tcp(rows, rng, 300, (-84, -78), (0.24, 0.4), False, 1, "attack_no_new_bssid_boundary_tcp")

    rng.shuffle(rows)
    return pd.DataFrame(rows)


def preprocess_like_deploy(df):
    prepared = df.copy()
    prepared["Protocol"] = prepared["Protocol"].map({"UDP": 0, "TCP": 1})
    prepared["new_BSSID"] = prepared["new_BSSID"].astype(int)
    return prepared[["Protocol", "RSSI", "new_BSSID", "RTT"]]


def print_eval(title, y_true, y_pred, scenarios):
    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = matrix.ravel()
    print()
    print(title)
    print("=" * len(title))
    print("Confusion Matrix")
    print("Rows = actual, columns = predicted")
    print("Labels: [0 Normal, 1 Evil Twin]")
    print(matrix)
    print()
    print(f"TN(normal->normal): {tn}")
    print(f"FP(normal->attack): {fp}")
    print(f"FN(attack->normal): {fn}")
    print(f"TP(attack->attack): {tp}")
    print(f"Accuracy: {accuracy_score(y_true, y_pred):.4f}")
    print()
    print(classification_report(y_true, y_pred, labels=[0, 1], target_names=["Normal", "Evil Twin"]))

    scenario_df = pd.DataFrame(
        {"scenario": scenarios, "true": y_true, "pred": y_pred}
    )
    scenario_df["correct"] = scenario_df["true"] == scenario_df["pred"]
    print("Scenario Accuracy")
    for scenario, score in scenario_df.groupby("scenario")["correct"].mean().sort_index().items():
        print(f"{scenario}: {score:.4f}")


def backup_current_models():
    stamp = time.strftime("%Y%m%d_%H%M%S")
    backups = []
    for path in (MODEL_PATH, SCALER_PATH):
        if path.exists():
            backup = path.with_suffix(path.suffix + f".backup_{stamp}")
            shutil.copy2(path, backup)
            backups.append(backup.name)
    return backups


def main():
    df = build_training_dataset()
    x = preprocess_like_deploy(df)
    y = df["is_attack"]

    x_train, x_test, y_train, y_test, scenario_train, scenario_test = train_test_split(
        x,
        y,
        df["scenario"],
        test_size=0.3,
        random_state=RANDOM_SEED,
        stratify=y,
    )

    scaler = StandardScaler()
    x_train_scaled = scaler.fit_transform(x_train)
    x_test_scaled = scaler.transform(x_test)

    model = SVC(kernel="linear", C=1.0, probability=True, random_state=RANDOM_SEED)
    model.fit(x_train_scaled, y_train)

    y_pred = model.predict(x_test_scaled)

    print("Robust TwinGuard SVM Retraining")
    print("===============================")
    print(f"Training dataset size: {len(df)}")
    print(df.groupby(["scenario", "is_attack"]).size().to_string())

    print_eval("Hold-out Evaluation", y_test, y_pred, scenario_test)

    print()
    print("Linear SVM Coefficients")
    for name, coef in zip(["Protocol", "RSSI", "new_BSSID", "RTT"], model.coef_[0]):
        print(f"{name}: {coef:.6f}")
    print(f"intercept: {model.intercept_[0]:.6f}")

    backups = backup_current_models()
    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    print()
    print("Saved new model files")
    print(f"- {MODEL_PATH.name}")
    print(f"- {SCALER_PATH.name}")
    if backups:
        print("Backups")
        for backup in backups:
            print(f"- {backup}")


if __name__ == "__main__":
    main()
