import random

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

from evaluate_live_normal_synthetic_attack import (
    collect_live_normal_samples,
    preprocess_like_deploy,
)


def build_mixed_attack_samples(count=1500, seed=77):
    rng = random.Random(seed)
    rows = []

    new_bssid_count = count // 3
    clear_no_bssid_count = int(count * 7 / 15)
    boundary_no_bssid_count = count - new_bssid_count - clear_no_bssid_count

    for _ in range(int(new_bssid_count * 0.8)):
        rows.append(
            {
                "Protocol": "TCP",
                "RSSI": round(rng.uniform(-95, -65), 2),
                "RTT": round(rng.uniform(0.1, 1.2), 6),
                "new_BSSID": True,
                "is_attack": 1,
                "scenario": "attack_new_bssid_tcp",
            }
        )
    for _ in range(new_bssid_count - int(new_bssid_count * 0.8)):
        rows.append(
            {
                "Protocol": "UDP",
                "RSSI": round(rng.uniform(-95, -65), 2),
                "RTT": -1.0,
                "new_BSSID": True,
                "is_attack": 1,
                "scenario": "attack_new_bssid_udp",
            }
        )

    for _ in range(int(clear_no_bssid_count * 0.8)):
        rows.append(
            {
                "Protocol": "TCP",
                "RSSI": round(rng.uniform(-100, -85), 2),
                "RTT": round(rng.uniform(0.35, 1.5), 6),
                "new_BSSID": False,
                "is_attack": 1,
                "scenario": "attack_no_new_bssid_clear_tcp",
            }
        )
    for _ in range(clear_no_bssid_count - int(clear_no_bssid_count * 0.8)):
        rows.append(
            {
                "Protocol": "UDP",
                "RSSI": round(rng.uniform(-100, -85), 2),
                "RTT": -1.0,
                "new_BSSID": False,
                "is_attack": 1,
                "scenario": "attack_no_new_bssid_clear_udp",
            }
        )

    for _ in range(int(boundary_no_bssid_count * 0.8)):
        rows.append(
            {
                "Protocol": "TCP",
                "RSSI": round(rng.uniform(-84, -78), 2),
                "RTT": round(rng.uniform(0.24, 0.4), 6),
                "new_BSSID": False,
                "is_attack": 1,
                "scenario": "attack_no_new_bssid_boundary_tcp",
            }
        )
    for _ in range(boundary_no_bssid_count - int(boundary_no_bssid_count * 0.8)):
        rows.append(
            {
                "Protocol": "UDP",
                "RSSI": round(rng.uniform(-84, -78), 2),
                "RTT": -1.0,
                "new_BSSID": False,
                "is_attack": 1,
                "scenario": "attack_no_new_bssid_boundary_udp",
            }
        )

    rng.shuffle(rows)
    return rows


def main():
    normal_rows = collect_live_normal_samples(1500, "Wi-Fi", 1200)
    attack_rows = build_mixed_attack_samples(1500)
    df = pd.DataFrame(normal_rows + attack_rows)

    model = joblib.load("evil_twin_detector.pkl")
    scaler = joblib.load("feature_scaler.pkl")

    x = preprocess_like_deploy(df)
    y_true = df["is_attack"]
    y_pred = model.predict(scaler.transform(x))
    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = matrix.ravel()

    print()
    print("Live Normal + Mixed Attack Evaluation")
    print("=" * 45)
    print(f"Dataset size: {len(df)}")
    print(df.groupby(["scenario", "is_attack"]).size().to_string())
    print()
    print("Confusion Matrix")
    print("Rows = actual, columns = predicted")
    print("Labels: [0 Normal, 1 Evil Twin]")
    print(matrix)
    print()
    print(f"TN: {tn}")
    print(f"FP: {fp}")
    print(f"FN: {fn}")
    print(f"TP: {tp}")
    print(f"Accuracy: {accuracy_score(y_true, y_pred):.4f}")
    print()
    print(classification_report(y_true, y_pred, labels=[0, 1], target_names=["Normal", "Evil Twin"]))

    result = df.copy()
    result["predicted"] = y_pred
    result["correct"] = result["is_attack"] == result["predicted"]
    print("Scenario Accuracy")
    for scenario, score in result.groupby("scenario")["correct"].mean().sort_index().items():
        count = len(result[result["scenario"] == scenario])
        correct = int(result[result["scenario"] == scenario]["correct"].sum())
        print(f"{scenario}: {correct}/{count} = {score:.4f}")


if __name__ == "__main__":
    main()
