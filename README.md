# URLinsight ML Service (v1.0.0)

Layanan REST API berbasis FastAPI untuk deteksi URL phishing menggunakan model Random Forest (12 fitur) dan SHAP Local Explainability.

## 1. Persiapan & Instalasi
- Buat virtual environment: python -m venv venv
- Aktifkan (Windows): env\Scripts\activate
- Instal library: pip install -r requirements.txt

## 2. Konfigurasi Environment
Salin .env.example menjadi .env:
copy .env.example .env

## 3. Menjalankan Layanan API
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

- **Swagger UI:** http://127.0.0.1:8000/docs
- **Health Check:** GET /health
- **Prediksi URL:** POST /api/v1/predict (Wajib header Authorization: Bearer <URLINSIGHT_API_TOKEN>)

## 4. Catatan Keterbatasan
- Sistem hanya menganalisis teks URL (tidak membuka isi halaman website).
- Hasil klasifikasi merupakan indikasi pola URL, bukan jaminan keamanan mutlak.
