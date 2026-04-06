# PhishGuard — Phishing URL Detector

ML-powered phishing URL classifier with a React dashboard and FastAPI backend.
Trains on the real [PhiUSIIL Phishing URL Dataset](https://github.com/elaaatif/DATA-MINING-PhiUSIIL-Phishing-URL) and selects the best classifier automatically.
All dependencies run inside Docker — nothing is installed globally.

---

## Quick Start

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (includes Docker Compose)

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/phishing-detector.git
cd phishing-detector
```

### 2. Train the model (one-time, ~5–10 minutes)

```bash
docker compose --profile train build
docker compose --profile train run --rm train
```

This downloads the PhiUSIIL dataset, trains and compares 4 classifiers using 5-fold
cross-validation, and saves the best model to `backend/model/`.

Generated files:
- `backend/model/best_model.joblib` — the winning classifier
- `backend/model/metrics.json` — CV metrics used by the Methodology page

### 3. Start the app

```bash
docker compose up --build
```

| Service  | URL                        |
|----------|----------------------------|
| Frontend | http://localhost:5173      |
| API      | http://localhost:8000      |
| API Docs | http://localhost:8000/docs |

Open http://localhost:5173 in your browser.

### Stopping the app

```bash
docker compose down
```

---

## Project Structure

```
phishing-detector/
├── backend/
│   ├── features.py          # 31-feature URL extractor (lexical + structural + entropy)
│   ├── train.py             # Downloads dataset, trains 4 classifiers, saves best
│   ├── model_service.py     # Model loading + predict()
│   ├── main.py              # FastAPI app (POST /api/predict, GET /api/metrics)
│   ├── requirements.txt     # Runtime dependencies
│   ├── Dockerfile           # Backend image
│   └── Dockerfile.train     # Training image (separate, heavier deps)
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── DetectorPage.jsx    # URL scan UI with risk gauge
│   │   │   └── MethodologyPage.jsx # About page with live metrics from API
│   │   └── components/
│   │       ├── RiskGauge.jsx       # SVG semi-circle gauge (0-100)
│   │       └── FeatureList.jsx     # Suspicious signal cards with severity
│   └── Dockerfile
└── docker-compose.yml
```

---

## API

### `POST /api/predict`

**Request:**
```json
{ "url": "http://paypal-secure.tk/login" }
```

**Response:**
```json
{
  "url": "http://paypal-secure.tk/login",
  "label": "phishing",
  "probability": 0.9997,
  "risk_score": 100,
  "suspicious_features": [
    { "label": "Suspicious top-level domain", "description": "TLD is associated with free/abused registrars (e.g., .tk, .ml, .ga).", "severity": "high" },
    { "label": "Phishing-related keywords", "description": "3 phishing-related keyword(s) found in the URL.", "severity": "high" }
  ],
  "features": { "url_length": 29, "has_https": 0, ... }
}
```

### `GET /api/metrics`

Returns cross-validation results and feature importances used by the Methodology page.

---

## Model Comparison (5-Fold CV on PhiUSIIL Dataset)

Results from the last training run (12,500 URLs — 5,000 legitimate + 5,000 phishing + 2,500 augmented legitimate with paths):

| Model               | Accuracy | Precision | Recall  | F1      | ROC AUC |
|---------------------|----------|-----------|---------|---------|---------|
| Logistic Regression | 98.41%   | 99.81%    | 96.20%  | 97.97%  | 99.05%  |
| SVM (RBF)           | 98.50%   | 99.69%    | 96.54%  | 98.09%  | 99.34%  |
| Random Forest       | 98.33%   | 99.28%    | 96.52%  | 97.88%  | 99.56%  |
| **XGBoost**         | **98.85%** | **99.61%** | **97.50%** | **98.54%** | **99.53%** |

The best model (by F1) is selected automatically and used for all predictions.

---

## Features Extracted (31 total)

All features are computed purely from the URL string — no DNS lookups or page rendering.

| Group     | Features |
|-----------|----------|
| Lexical   | `url_length`, `domain_length`, `path_length`, `num_dots`, `num_hyphens`, `num_at`, `num_question`, `num_equals`, `num_percent`, `num_slash`, `num_ampersand`, `num_digits_url`, `num_digits_domain` |
| Structural | `has_at_symbol`, `has_double_slash`, `has_http_in_path`, `has_https`, `has_ip`, `url_depth`, `num_params`, `hex_count` |
| Domain/TLD | `suspicious_tld`, `tld_length`, `domain_has_hyphen`, `long_subdomain`, `num_subdomains`, `brand_in_subdomain`, `brand_in_domain_part` |
| Entropy   | `url_entropy`, `domain_entropy` |
| Keyword   | `keyword_count` |

---

## Dataset

**PhiUSIIL Phishing URL Dataset** — Hannousse, A. & Yahiouche, S. (2021).  
235,795 URLs (134,850 legitimate, 100,945 phishing). Balanced to 5,000 per class for training.

> The dataset is downloaded automatically during the training step. It is not included in this repository.

---

## References

1. Hannousse, A., & Yahiouche, S. (2021). Towards benchmark datasets for machine learning based website phishing detection. *Engineering Applications of Artificial Intelligence*, 104, 104347.
2. Chen, T., & Guestrin, C. (2016). XGBoost: A scalable tree boosting system. *ACM SIGKDD*, 785-794.
3. Breiman, L. (2001). Random forests. *Machine Learning*, 45(1), 5-32.




