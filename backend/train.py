"""
train.py — Phishing URL Detector: offline training pipeline.

Downloads the PhiUSIIL Phishing URL Dataset (Hannousse & Yahiouche, 2021),
extracts lexical features from real URLs, trains four classifiers,
serialises the best model (XGBoost), and writes model/metrics.json
for the frontend methodology page.

Run inside Docker:
    docker compose --profile train run --rm train
"""

import csv
import io
import json
import os
import random
import urllib.request
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from xgboost import XGBClassifier
import joblib

from features import extract_features, FEATURE_NAMES

SEED = 42
random.seed(SEED)
np.random.seed(SEED)

MODEL_DIR = Path("model")
MODEL_DIR.mkdir(exist_ok=True)

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# Dataset download & loading
# ---------------------------------------------------------------------------
DATASET_URL = (
    "https://raw.githubusercontent.com/elaaatif/"
    "DATA-MINING-PhiUSIIL-Phishing-URL/main/"
    "PhiUSIIL_Phishing_URL_Dataset.csv"
)
DATASET_PATH = DATA_DIR / "PhiUSIIL_Phishing_URL_Dataset.csv"

SAMPLE_PER_CLASS = 5000  # 10k total, balanced


def download_dataset() -> Path:
    """Download the PhiUSIIL dataset if not already cached."""
    if DATASET_PATH.exists():
        print(f"Dataset already cached at {DATASET_PATH}")
        return DATASET_PATH

    print(f"Downloading PhiUSIIL dataset from GitHub...")
    urllib.request.urlretrieve(DATASET_URL, DATASET_PATH)
    print(f"Saved → {DATASET_PATH}")
    return DATASET_PATH


def load_and_sample(path: Path) -> pd.DataFrame:
    """Load CSV, extract URL + label, sample balanced subset."""
    print("Loading dataset...")
    df = pd.read_csv(path, low_memory=False)

    # Dataset has 'URL' and 'label' columns
    # label: 1 = legitimate, 0 = phishing  (PhiUSIIL convention)
    # We remap: 0 = legitimate, 1 = phishing (standard ML convention)
    url_col = None
    label_col = None

    for col in df.columns:
        if col.strip().lower() == "url":
            url_col = col
        if col.strip().lower() == "label":
            label_col = col

    if url_col is None or label_col is None:
        raise ValueError(
            f"Could not find URL/label columns. Columns: {list(df.columns)}"
        )

    df = df[[url_col, label_col]].copy()
    df.columns = ["url", "label_raw"]

    # Drop rows with missing URLs
    df = df.dropna(subset=["url"])
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"].str.len() > 0]

    # Determine label mapping by inspecting unique values
    unique_labels = sorted(df["label_raw"].unique())
    print(f"  Raw label values: {unique_labels}")
    print(f"  Total rows: {len(df):,}")

    if set(unique_labels) == {0, 1}:
        counts = df["label_raw"].value_counts()
        print(f"  Label distribution: {dict(counts)}")

        # Auto-detect: legitimate URLs use HTTPS far more often than phishing.
        # Check which raw label value has the higher HTTPS rate.
        urls_lower = df["url"].str.lower()
        https_rate_0 = urls_lower[df["label_raw"] == 0].str.startswith("https").mean()
        https_rate_1 = urls_lower[df["label_raw"] == 1].str.startswith("https").mean()
        print(f"  HTTPS rate for label_raw=0: {https_rate_0:.2%}")
        print(f"  HTTPS rate for label_raw=1: {https_rate_1:.2%}")

        if https_rate_1 > https_rate_0:
            # label_raw=1 is legitimate (higher HTTPS) → flip so 1=phishing
            print("  → Detected: label_raw 1=legitimate, 0=phishing. Remapping.")
            df["label"] = (1 - df["label_raw"]).astype(int)
        else:
            # label_raw=1 is phishing (lower HTTPS) → already correct
            print("  → Detected: label_raw 0=legitimate, 1=phishing. No remap needed.")
            df["label"] = df["label_raw"].astype(int)
    else:
        # Try string labels
        df["label_raw_str"] = df["label_raw"].astype(str).str.lower()
        df["label"] = df["label_raw_str"].map(
            {"phishing": 1, "legitimate": 0, "legit": 0, "benign": 0,
             "malicious": 1, "bad": 1, "good": 0}
        )
        df = df.dropna(subset=["label"])
        df["label"] = df["label"].astype(int)

    legit = df[df["label"] == 0]
    phish = df[df["label"] == 1]
    print(f"  Legitimate: {len(legit):,}  |  Phishing: {len(phish):,}")

    # Sanity check: print sample URLs from each class
    print("\n  Sample LEGITIMATE URLs:")
    for u in legit["url"].head(3).values:
        print(f"    {u}")
    print("  Sample PHISHING URLs:")
    for u in phish["url"].head(3).values:
        print(f"    {u}")

    # Balanced sample
    n = min(SAMPLE_PER_CLASS, len(legit), len(phish))
    print(f"  Sampling {n:,} per class ({n*2:,} total)...")
    legit_sample = legit.sample(n=n, random_state=SEED)
    phish_sample = phish.sample(n=n, random_state=SEED)

    # ── Data augmentation ─────────────────────────────────────────────
    # The PhiUSIIL legitimate URLs are root domains only (no paths).
    # This biases path_length / url_depth / num_slash to zero for the
    # legitimate class.  Augment by appending common path patterns to a
    # subset of legitimate URLs so the model learns that paths are
    # normal for legitimate sites too.
    COMMON_PATHS = [
        # Single-segment paths
        "/about", "/contact", "/login", "/search", "/help",
        "/products", "/services", "/blog", "/faq", "/support",
        "/terms", "/privacy", "/settings", "/dashboard", "/profile",
        "/docs", "/api", "/pricing", "/news", "/careers",
        "/wiki", "/forum", "/store", "/checkout", "/download",
        # Two-segment paths
        "/docs/getting-started", "/blog/2024/latest-news",
        "/products/category/item", "/api/v2/users",
        "/help/articles/how-to", "/en/support/contact-us",
        "/account/settings/profile", "/resources/guides/intro",
        "/community/forums/general", "/developers/docs/reference",
        "/user/repository", "/org/project", "/wiki/Main_Page",
        "/search/results", "/store/products", "/en/docs",
        # Three+ segment paths (deep but legitimate)
        "/docs/api/v2/reference", "/blog/2024/03/update",
        "/en/help/articles/guide", "/user/repo/tree/main",
        "/wiki/Category/Article/Section",
        "/products/electronics/phones/latest",
    ]
    rng = np.random.RandomState(SEED)
    aug_rows = []
    # Augment ~50% of legitimate URLs with a random path
    aug_indices = rng.choice(len(legit_sample), size=int(n * 0.5), replace=False)
    for idx in aug_indices:
        row = legit_sample.iloc[idx].copy()
        path_suffix = rng.choice(COMMON_PATHS)
        url = row["url"].rstrip("/")
        row["url"] = url + path_suffix
        aug_rows.append(row)

    aug_df = pd.DataFrame(aug_rows)
    print(f"  Augmented {len(aug_df):,} legitimate URLs with paths")

    sampled = pd.concat([
        legit_sample, aug_df, phish_sample,
    ]).reset_index(drop=True)

    return sampled


def extract_all_features(df: pd.DataFrame) -> pd.DataFrame:
    """Run feature extraction on every URL."""
    print(f"Extracting {len(FEATURE_NAMES)} features from {len(df):,} URLs...")
    records = []
    for i, row in df.iterrows():
        feats = extract_features(row["url"])
        feats["label"] = row["label"]
        records.append(feats)
        if (i + 1) % 2000 == 0:
            print(f"  {i+1:,} / {len(df):,} done")

    result = pd.DataFrame(records)
    print(f"  Feature extraction complete.")
    return result


# ---------------------------------------------------------------------------
# Training & evaluation
# ---------------------------------------------------------------------------

def _build_classifiers() -> dict:
    """Return a fresh dict of untrained classifiers."""
    return {
        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(max_iter=1000, random_state=SEED)),
        ]),
        "SVM (RBF)": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", SVC(kernel="rbf", probability=True, random_state=SEED)),
        ]),
        "Random Forest": RandomForestClassifier(
            n_estimators=200, max_depth=12, n_jobs=-1, random_state=SEED
        ),
        "XGBoost": XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,

            eval_metric="logloss",
            random_state=SEED,
            n_jobs=-1,
        ),
    }


def evaluate_models(X: np.ndarray, y: np.ndarray) -> dict:
    """Run 5-fold CV on four classifiers and return metrics dict."""
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
    scoring = ["accuracy", "precision", "recall", "f1", "roc_auc"]
    classifiers = _build_classifiers()

    results = {}
    for name, model in classifiers.items():
        print(f"  Evaluating {name}...")
        cv_res = cross_validate(model, X, y, cv=cv, scoring=scoring, n_jobs=1)
        results[name] = {
            "accuracy":  round(float(cv_res["test_accuracy"].mean()), 4),
            "precision": round(float(cv_res["test_precision"].mean()), 4),
            "recall":    round(float(cv_res["test_recall"].mean()), 4),
            "f1":        round(float(cv_res["test_f1"].mean()), 4),
            "roc_auc":   round(float(cv_res["test_roc_auc"].mean()), 4),
        }
        print(
            f"    acc={results[name]['accuracy']:.4f}  "
            f"f1={results[name]['f1']:.4f}  "
            f"auc={results[name]['roc_auc']:.4f}"
        )
    return results


def train_final_model(X: np.ndarray, y: np.ndarray, model_name: str):
    """Train the winning classifier on the full dataset."""
    print(f"Training final model ({model_name}) on full dataset...")
    classifiers = _build_classifiers()
    model = classifiers[model_name]
    model.fit(X, y)
    return model


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    path = download_dataset()
    df_raw = load_and_sample(path)
    df = extract_all_features(df_raw)

    X = df[FEATURE_NAMES].values.astype(np.float32)
    y = df["label"].values

    print("\n--- Cross-validation comparison ---")
    metrics = evaluate_models(X, y)

    # Determine best model by F1
    best_name = max(metrics, key=lambda m: metrics[m]["f1"])
    print(f"\nBest model by F1: {best_name}")

    model = train_final_model(X, y, best_name)

    # Feature importances (tree models have .feature_importances_,
    # pipelines wrap the classifier inside .named_steps["clf"])
    raw_model = model
    if hasattr(model, "named_steps"):
        raw_model = model.named_steps["clf"]

    if hasattr(raw_model, "feature_importances_"):
        importances = {
            name: round(float(score), 6)
            for name, score in zip(FEATURE_NAMES, raw_model.feature_importances_)
        }
    elif hasattr(raw_model, "coef_"):
        # Logistic Regression / SVM — use absolute coefficient magnitude
        coefs = np.abs(raw_model.coef_[0])
        coefs = coefs / coefs.sum()  # normalize to sum=1
        importances = {
            name: round(float(score), 6)
            for name, score in zip(FEATURE_NAMES, coefs)
        }
    else:
        importances = {name: 0.0 for name in FEATURE_NAMES}

    # Persist — include phishing_class_index so inference knows
    # which column of predict_proba corresponds to "phishing"
    model_path = MODEL_DIR / "best_model.joblib"
    phishing_class_index = int(np.where(model.classes_ == 1)[0][0]) if hasattr(model, "classes_") else 1
    joblib.dump({
        "model": model,
        "feature_names": FEATURE_NAMES,
        "phishing_class_index": phishing_class_index,
    }, model_path)
    print(f"\nModel saved → {model_path}")

    metrics_payload = {
        "comparison": metrics,
        "feature_importances": importances,
        "best_model": best_name,
        "dataset": {
            "total_samples": len(df),
            "phishing": int(y.sum()),
            "legitimate": int((y == 0).sum()),
            "features": len(FEATURE_NAMES),
            "cv_folds": 5,
            "source": "PhiUSIIL Phishing URL Dataset (Hannousse & Yahiouche, 2021)",
        },
    }

    metrics_path = MODEL_DIR / "metrics.json"
    with open(metrics_path, "w") as f:
        json.dump(metrics_payload, f, indent=2)
    print(f"Metrics saved → {metrics_path}")

    print("\n=== Final CV Results ===")
    for model_name, m in metrics.items():
        marker = " ★" if model_name == best_name else ""
        print(
            f"{model_name:25s}  acc={m['accuracy']:.4f}  "
            f"prec={m['precision']:.4f}  rec={m['recall']:.4f}  "
            f"f1={m['f1']:.4f}  auc={m['roc_auc']:.4f}{marker}"
        )
    print("\nDone.")


if __name__ == "__main__":
    main()
