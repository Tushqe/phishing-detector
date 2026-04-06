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



