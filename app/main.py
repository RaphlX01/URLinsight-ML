from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib
import math
from collections import Counter
from urllib.parse import urlparse

# 1. Inisialisasi API
app = FastAPI(title="URLinsight ML Service")

# 2. Load Model dengan Try-Except yang benar
try:
    bundle_rf = joblib.load("models/rf_baseline.joblib")
except FileNotFoundError:
    print("ERROR: File model tidak ditemukan. Pastikan path-nya benar.")
    bundle_rf = None

# 3. Format Request
class PredictRequest(BaseModel):
    url: str

# 4. Fungsi Ekstraksi Fitur
def shannon_entropy(s):
    if not s: 
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())

def extract_features(url):
    url = str(url)
    host = urlparse(url).netloc
    return [
        len(url), 
        url.count("."), 
        sum(ch.isdigit() for ch in url),
        int(url.startswith("https://")), 
        len(host), 
        shannon_entropy(url)
    ]

# 5. Endpoint Prediksi
@app.post("/predict")
def predict(req: PredictRequest):
    if not req.url.strip():
        raise HTTPException(status_code=422, detail="URL tidak boleh kosong")
    
    if bundle_rf is None:
        raise HTTPException(status_code=503, detail="Model Machine Learning belum siap.")

    # Ekstrak fitur & Prediksi
    fitur = extract_features(req.url)
    prediksi = int(bundle_rf.predict([fitur])[0])
    
    label = "phishing" if prediksi == 1 else "legitimate"
    
    return {
        "status": "success",
        "prediction": label,
        "message": f"Model mendeteksi indikasi {label} pada URL ini."
    }

# 6. Endpoint Health Check
@app.get("/health")
def health():
    return {"status": "ready"}