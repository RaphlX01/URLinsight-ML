import os
import sys
import uuid
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import joblib
import numpy as np
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from src.preprocessing import is_valid_url
from src.features import FEATURE_ORDER, FEATURE_DESCRIPTIONS, build_indicators

load_dotenv()

API_TOKEN = os.getenv("URLINSIGHT_API_TOKEN", "urlinsight-secret-token-2026")
MODEL_PATH = os.getenv(
    "URLINSIGHT_MODEL_PATH",
    os.path.join(ROOT_DIR, "models", "rf_v1.0.0.joblib"),
)

app = FastAPI(
    title="URLinsight ML Service",
    version="1.0.0",
    description="REST API Deteksi URL Phishing dengan SHAP Local Explainability",
)

security = HTTPBearer(auto_error=False)
model_bundle = None

try:
    if os.path.exists(MODEL_PATH):
        model_bundle = joblib.load(MODEL_PATH)
except Exception as exc:
    print(f"[STARTUP ERROR] Gagal memuat model: {exc}")
    model_bundle = None


class PredictRequest(BaseModel):
    url: str


def error_response(status_code: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "success": False,
            "error": {
                "code": code,
                "message": message,
            },
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return error_response(
        400,
        "INVALID_REQUEST",
        "Body request harus JSON valid dan memiliki field 'url'",
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if isinstance(exc.detail, dict) and "code" in exc.detail:
        return error_response(exc.status_code, exc.detail["code"], exc.detail["message"])
    return error_response(exc.status_code, "INTERNAL_ERROR", str(exc.detail))


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    return error_response(500, "INTERNAL_ERROR", "Terjadi kesalahan internal pada ML Service")


def verify_bearer_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if (
        credentials is None
        or credentials.scheme.lower() != "bearer"
        or credentials.credentials != API_TOKEN
    ):
        raise HTTPException(
            status_code=401,
            detail={
                "code": "UNAUTHORIZED",
                "message": "Bearer Token tidak ada atau tidak valid",
            },
        )
    return credentials.credentials


def compute_shap_explanation(
    explainer, feature_vec: list, indicators: list[dict], prediction: str
) -> dict:
    x_arr = np.array([feature_vec], dtype=float)
    raw_shap = explainer.shap_values(x_arr)

    if isinstance(raw_shap, list):
        phishing_contrib = np.array(raw_shap[1])[0]
    elif raw_shap.ndim == 3:
        phishing_contrib = raw_shap[0, :, 1]
    else:
        phishing_contrib = raw_shap[0]

    indicator_values = {item["name"]: item["value"] for item in indicators}
    ranked = sorted(
        zip(FEATURE_ORDER, phishing_contrib),
        key=lambda item: abs(item[1]),
        reverse=True,
    )

    top_features = []
    for feat_name, contrib in ranked[:3]:
        val = indicator_values[feat_name]
        direction = "phishing" if contrib > 0 else "legitimate"
        top_features.append(
            {
                "name": feat_name,
                "value": val,
                "contribution": round(float(abs(contrib)), 4),
                "direction": direction,
            }
        )

    supporting = [
        f"{FEATURE_DESCRIPTIONS[item['name']].lower()} ({item['value']})"
        for item in top_features
        if item["direction"] == prediction
    ]
    if supporting:
        summary = f"Prediksi {prediction} terutama dipengaruhi oleh {', '.join(supporting)}."
    else:
        summary = f"Prediksi {prediction} didasarkan pada kombinasi keseluruhan struktur teks URL."

    return {
        "method": "SHAP",
        "summary": summary,
        "top_features": top_features,
    }


@app.get("/health")
def health():
    if model_bundle is None:
        return error_response(503, "MODEL_UNAVAILABLE", "Model belum siap atau tidak tersedia")
    return {
        "success": True,
        "status": "ready",
        "model_version": model_bundle["version"],
    }


@app.post("/api/v1/predict")
def predict(req: PredictRequest, _token: str = Depends(verify_bearer_token)):
    start_time = time.perf_counter()

    if model_bundle is None:
        return error_response(503, "MODEL_UNAVAILABLE", "Model belum siap atau tidak tersedia")

    valid, result = is_valid_url(req.url)
    if not valid:
        return error_response(422, "INVALID_URL", result)

    normalized_url = result
    domain = urlparse(normalized_url).hostname or ""

    feature_vec, indicators = build_indicators(normalized_url)
    model = model_bundle["model"]
    label_map = model_bundle["label_map"]

    pred_idx = int(model.predict([feature_vec])[0])
    proba = model.predict_proba([feature_vec])[0]

    prediction_label = label_map[pred_idx]
    confidence = round(float(proba[pred_idx]), 4)

    explanation = compute_shap_explanation(
        model_bundle["explainer"], feature_vec, indicators, prediction_label
    )

    elapsed_ms = int(round((time.perf_counter() - start_time) * 1000))
    analyzed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "success": True,
        "data": {
            "scan_id": uuid.uuid4().hex[:8],
            "target": {
                "url": normalized_url,
                "domain": domain,
            },
            "classification": {
                "prediction": prediction_label,
                "confidence": confidence,
            },
            "analysis": {
                "indicators": indicators,
                "explanation": explanation,
            },
            "metadata": {
                "model_version": model_bundle["version"],
                "processing_time_ms": elapsed_ms,
                "analyzed_at": analyzed_at,
            },
        },
    }
