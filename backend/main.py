"""
main.py — FastAPI application for the Phishing URL Detector.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

from model_service import predict, get_metrics

app = FastAPI(
    title="Phishing URL Detector API",
    version="1.0.0",
    description="XGBoost-backed phishing URL detection with explainable feature output.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


class PredictRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def url_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("url must not be empty")
        if len(v) > 2048:
            raise ValueError("url exceeds maximum length of 2048 characters")
        return v


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/api/predict")
def api_predict(body: PredictRequest) -> dict:
    try:
        result = predict(body.url)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Prediction error: {exc}")
    return result


@app.get("/api/metrics")
def api_metrics() -> dict:
    return get_metrics()
