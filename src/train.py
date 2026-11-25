import os
import json
import random
import joblib
import shap
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

from preprocessing import load_and_clean_datasets
from features import FEATURE_ORDER, extract_features_vector

MODEL_VERSION = "1.0.0"
BENIGN_PATHS = [
    "/about",
    "/contact",
    "/docs/guide",
    "/news/latest",
    "/products/overview",
    "/projects/repo",
]


def augment_legitimate_urls(train_df: pd.DataFrame) -> pd.DataFrame:
    """
    Menambah variasi URL aman (target == 0) tanpa awalan 'www.' dan dengan path normal
    agar model tidak bias menganggap domain tanpa 'www.' sebagai phishing.
    """
    rng = random.Random(42)
    legit_urls = train_df[train_df["target"] == 0]["url_norm"].tolist()
    augmented = []

    for url in legit_urls:
        no_www = url.replace("://www.", "://", 1)
        if no_www != url:
            augmented.append(no_www)
            if rng.random() < 0.35:
                augmented.append(f"{no_www}{rng.choice(BENIGN_PATHS)}")

    aug_df = pd.DataFrame({"url_norm": list(set(augmented)), "target": 0})
    return pd.concat([train_df[["url_norm", "target"]], aug_df], ignore_index=True)


def main():
    os.makedirs("data/processed", exist_ok=True)
    os.makedirs("models", exist_ok=True)
    os.makedirs("docs", exist_ok=True)

    print("1. Memuat dan membersihkan dataset...")
    df_phi, df_legit = load_and_clean_datasets(
        "data/raw/PhiUSIIL_Phishing_URL_Dataset.csv",
        "data/raw/url_features_extracted1.csv",
    )

    df_combined = pd.concat(
        [
            df_phi[["url_norm", "target"]].assign(source="PhiUSIIL"),
            df_legit[["url_norm", "target"]].assign(source="LegitPhish"),
        ],
        ignore_index=True,
    )
    df_combined.to_csv("data/processed/urls_cleaned.csv", index=False)

    train_df, test_df = train_test_split(
        df_combined, test_size=0.2, stratify=df_combined["target"], random_state=42
    )
    train_aug_df = augment_legitimate_urls(train_df)

    print("2. Mengekstrak 12 fitur (termasuk augmentasi URL aman)...")
    X_train = pd.DataFrame(
        train_aug_df["url_norm"].apply(extract_features_vector).tolist(),
        columns=FEATURE_ORDER,
    )
    y_train = train_aug_df["target"]

    X_test = pd.DataFrame(
        test_df["url_norm"].apply(extract_features_vector).tolist(),
        columns=FEATURE_ORDER,
    )
    y_test = test_df["target"]

    print("3. Melatih Random Forest final...")
    rf_model = RandomForestClassifier(
        n_estimators=150,
        max_depth=24,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
    )
    rf_model.fit(X_train, y_train)

    y_pred = rf_model.predict(X_test)
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()

    report = {
        "model_version": MODEL_VERSION,
        "features": FEATURE_ORDER,
        "metrics": {
            "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
            "precision_phishing": round(float(precision_score(y_test, y_pred)), 4),
            "recall_phishing": round(float(recall_score(y_test, y_pred)), 4),
            "f1_phishing": round(float(f1_score(y_test, y_pred)), 4),
        },
        "confusion_matrix": {
            "TP": int(tp),
            "FP": int(fp),
            "TN": int(tn),
            "FN": int(fn),
        },
    }

    with open("docs/model_evaluation_v1.0.0.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("4. Membangun SHAP TreeExplainer dan menyimpan artefak model...")
    explainer = shap.TreeExplainer(rf_model)

    bundle = {
        "model": rf_model,
        "explainer": explainer,
        "features": FEATURE_ORDER,
        "version": MODEL_VERSION,
        "label_map": {1: "phishing", 0: "legitimate"},
    }
    joblib.dump(bundle, f"models/rf_v{MODEL_VERSION}.joblib", compress=3)
    print("Selesai! Evaluasi:", json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
