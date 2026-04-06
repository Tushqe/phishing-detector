"""
model_service.py — loads the trained model and exposes
a single predict() function used by the FastAPI layer.
"""

import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from features import extract_features, get_suspicious_features, FEATURE_NAMES

_MODEL_PATH = Path(__file__).parent / "model" / "best_model.joblib"
_METRICS_PATH = Path(__file__).parent / "model" / "metrics.json"

_artifact: dict[str, Any] | None = None
_metrics: dict[str, Any] | None = None


def _ensure_loaded() -> None:
    global _artifact, _metrics
    if _artifact is not None:
        return
    if not _MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Model file not found at {_MODEL_PATH}. "
            "Run the training container first: docker compose --profile train run --rm train"
        )
    _artifact = joblib.load(_MODEL_PATH)
    if _METRICS_PATH.exists():
        with open(_METRICS_PATH) as f:
            _metrics = json.load(f)


def predict(url: str) -> dict[str, Any]:
    """
    Returns:
        {
          "url": str,
          "label": "phishing" | "legitimate",
          "probability": float,        # P(phishing)
          "risk_score": int,           # 0-100
          "suspicious_features": [...],
          "features": {raw feature dict},
        }
    """
    _ensure_loaded()
    model = _artifact["model"]
    phish_idx = _artifact.get("phishing_class_index", 1)

    feats = extract_features(url)
    X = np.array([[feats[n] for n in FEATURE_NAMES]], dtype=np.float32)

    prob_phish: float = float(model.predict_proba(X)[0][phish_idx])
    label = "phishing" if prob_phish >= 0.5 else "legitimate"
    risk_score = round(prob_phish * 100)

    suspicious = get_suspicious_features(feats)

    return {
        "url": url,
        "label": label,
        "probability": round(prob_phish, 4),
        "risk_score": risk_score,
        "suspicious_features": suspicious,
        "features": feats,
    }


def get_metrics() -> dict[str, Any]:
    _ensure_loaded()
    return _metrics or {}
