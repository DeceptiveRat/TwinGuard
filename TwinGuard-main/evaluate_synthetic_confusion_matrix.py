import random

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


MODEL_PATH = "evil_twin_detector.pkl"
SCALER_PATH = "feature_scaler.pkl"
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


def build_dataset(seed=RANDOM_SEED):
    rng = random.Random(seed)
    rows = []

    # Clear normal: stable BSSID, good signal, low RTT.
    for _ in range(70):
        rows.append(tcp_sample(rng, (-68, -45), (0.0, 0.08), False, 0, "normal_clear"))
    for _ in range(30):
        rows.append(udp_sample(rng, (-68, -45), False, 0, "normal_clear"))

    # Ambiguous normal: weak or slightly delayed network, but BSSID is unchanged.
    for _ in range(40):
        rows.append(tcp_sample(rng, (-80, -70), (0.08, 0.18), False, 0, "normal_ambiguous"))
    for _ in range(10):
        rows.append(udp_sample(rng, (-80, -70), False, 0, "normal_ambiguous"))

    # Clear attack: new BSSID, weak signal, high RTT.
    for _ in range(80):
        rows.append(tcp_sample(rng, (-95, -80), (0.3, 1.2), True, 1, "attack_clear"))
    for _ in range(20):
        rows.append(udp_sample(rng, (-95, -80), True, 1, "attack_clear"))

    # Ambiguous attack: new BSSID, but signal/RTT are not extremely bad.
    for _ in range(40):
        rows.append(tcp_sample(rng, (-78, -65), (0.1, 0.3), True, 1, "attack_ambiguous"))
    for _ in range(10):
        rows.append(udp_sample(rng, (-78, -65), True, 1, "attack_ambiguous"))

    rng.shuffle(rows)
    return pd.DataFrame(rows)


def preprocess_like_deploy(df):
    protocol_map = {"UDP": 0, "TCP": 1}
    prepared = df.copy()
    prepared["Protocol"] = prepared["Protocol"].map(protocol_map)
    prepared["new_BSSID"] = prepared["new_BSSID"].astype(int)
    return prepared[["Protocol", "RSSI", "new_BSSID", "RTT"]]


def main():
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    df = build_dataset()
    x = preprocess_like_deploy(df)
    y_true = df["is_attack"]

    x_scaled = scaler.transform(x)
    y_pred = model.predict(x_scaled)

    print("Synthetic TwinGuard Evaluation")
    print("=" * 36)
    print(f"Dataset size: {len(df)}")
    print("Normal label: 0")
    print("Attack label: 1")
    print()

    print("Dataset composition")
    print(df.groupby(["scenario", "is_attack"]).size().to_string())
    print()

    print("Confusion Matrix")
    print("Rows = actual, columns = predicted")
    print("Labels: [0 Normal, 1 Evil Twin]")
    print(confusion_matrix(y_true, y_pred, labels=[0, 1]))
    print()

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    print(f"TN(normal->normal): {tn}")
    print(f"FP(normal->attack): {fp}")
    print(f"FN(attack->normal): {fn}")
    print(f"TP(attack->attack): {tp}")
    print()

    print(f"Accuracy: {accuracy_score(y_true, y_pred):.4f}")
    print()
    print("Classification Report")
    print(classification_report(y_true, y_pred, labels=[0, 1], target_names=["Normal", "Evil Twin"]))

    print("Scenario Accuracy")
    result_df = df.copy()
    result_df["predicted"] = y_pred
    result_df["correct"] = result_df["is_attack"] == result_df["predicted"]
    scenario_accuracy = result_df.groupby("scenario")["correct"].mean().sort_index()
    for scenario, score in scenario_accuracy.items():
        print(f"{scenario}: {score:.4f}")


if __name__ == "__main__":
    main()
