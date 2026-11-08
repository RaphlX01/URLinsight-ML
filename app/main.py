from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import joblib
import math
import time
import uuid
from datetime import datetime, timezone
from collections import Counter
from urllib.parse import urlparse

app = FastAPI(title="URLinsight ML Service")
SECRET_TOKEN = "urlinsight-secret-token-2026"
security = HTTPBearer()

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if credentials.credentials != SECRET_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid Token")
    return credentials.credentials

# Load Model
try:
    model = joblib.load("models/rf_baseline.joblib")
except Exception:
    model = None

class PredictRequest(BaseModel):
    url: str

def shannon_entropy(s):
    if not s: return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())

def extract_features(url):
    url = str(url)
    host = urlparse(url).netloc
    return [
        len(url), url.count("."), sum(ch.isdigit() for ch in url),
        int(url.startswith("https://")), len(host), shannon_entropy(url)
    ]

@app.post("/api/v1/predict")
def predict(req: PredictRequest, token: str = Depends(verify_token)):
    start_time = time.time()
    
    if not req.url.strip():
        return JSONResponse(status_code=422, content={"success": False, "error": {"code": "INVALID_URL", "message": "URL invalid"}})
    if model is None:
        return JSONResponse(status_code=503, content={"success": False, "error": {"code": "MODEL_UNAVAILABLE", "message": "Model offline"}})

    try:
        # Ekstraksi & Prediksi
        fitur = extract_features(req.url)
        prediksi = int(model.predict([fitur])[0])
        probabilitas = model.predict_proba([fitur])[0]
        confidence = float(max(probabilitas))
        label = "phishing" if prediksi == 1 else "legitimate"
        
        # --- LOGIKA RISK LEVEL ---
        risk_level = "low"
        if label == "phishing":
            risk_level = "high" if confidence > 0.8 else "medium"
        elif label == "legitimate":
            risk_level = "low"
            confidence = float(probabilitas[0]) # Ambil probabilitas legit

        # --- FORMAT INDICATORS (Persis minta temanmu) ---
        indicators = [
            {
                "name": "url_length",
                "value": fitur[0],
                "interpretation": "Relatif panjang" if fitur[0] > 75 else "Normal",
                "severity": "low" # Temanmu minta 'low' di contoh ini
            },
            {
                "name": "subdomain_count",
                "value": max(0, fitur[1] - 1),
                "interpretation": "Memiliki beberapa subdomain" if fitur[1] > 2 else "Normal",
                "severity": "medium"
            },
            {
                "name": "uses_https",
                "value": bool(fitur[3]),
                "interpretation": "Menggunakan HTTPS" if fitur[3] == 1 else "Tidak menggunakan HTTPS",
                "severity": "info"
            }
        ]

        processing_time = int((time.time() - start_time) * 1000)
        analyzed_at = datetime.now(timezone.utc).isoformat()

        # --- RETURN JSON PERSIS SEPERTI REQUEST ---
        return {
            "success": True,
            "data": {
                "scan_id": str(uuid.uuid4())[:8],
                "target": {
                    "url": req.url,
                    "domain": urlparse(req.url).netloc
                },
                "classification": {
                    "prediction": label,
                    "confidence": round(confidence, 2), # Dibuat 2 desimal biar kayak 0.97
                    "risk_level": risk_level
                },
                "analysis": {
                    "indicators": indicators,
                    "explanation": {
                        "method": "SHAP",
                        "summary": f"Beberapa karakteristik URL berkontribusi terhadap prediksi {label}.",
                        "top_features": [] # Dikosongkan sesuai request dia
                    }
                },
                "metadata": {
                    "model_version": "1.0.0",
                    "processing_time_ms": processing_time,
                    "analyzed_at": analyzed_at
                }
            }
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"success": False, "error": {"code": "INTERNAL_ERROR", "message": str(e)}})