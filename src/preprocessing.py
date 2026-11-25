import re
from urllib.parse import urlparse
import pandas as pd

MAX_URL_LENGTH = 2048

def normalize_url(raw_url: str) -> str:
    """
    Aturan normalisasi tunggal (dipakai saat training & API inference):
    1. Hapus spasi di awal/akhir.
    2. Hapus fragmen (#...).
    3. Tambahkan skema sementara http:// jika tanpa skema agar urlparse konsisten.
    4. Ubah skema dan hostname menjadi huruf kecil (path & query tetap peka huruf).
    5. Hapus trailing slash '/' di akhir jika path kosong.
    """
    if raw_url is None or not isinstance(raw_url, str):
        return ""

    url = raw_url.strip()
    if not url or " " in url:
        return ""

    # Hapus fragmen
    url = url.split("#")[0]

    has_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url))
    parse_target = url if has_scheme else f"http://{url}"

    parsed = urlparse(parse_target)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    if not netloc or "." not in netloc and not re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", netloc):
        return ""

    path = parsed.path or ""
    if path == "/":
        path = ""

    rebuilt = f"{scheme}://{netloc}{path}"
    if parsed.params:
        rebuilt += f";{parsed.params}"
    if parsed.query:
        rebuilt += f"?{parsed.query}"

    return rebuilt


def is_valid_url(raw_url: str) -> tuple[bool, str]:
    """Validasi masukan URL sesuai kontrak error 422."""
    if not raw_url or not isinstance(raw_url, str) or not raw_url.strip():
        return False, "URL tidak boleh kosong"
    if len(raw_url.strip()) > MAX_URL_LENGTH:
        return False, f"Panjang URL melebihi batas maksimum ({MAX_URL_LENGTH} karakter)"
    normalized = normalize_url(raw_url)
    if not normalized:
        return False, "Format URL tidak valid"
    return True, normalized


def load_and_clean_datasets(phi_path: str, legit_path: str):
    """
    Memuat dataset mentah, menghapus duplikat, menghilangkan tumpang tindih
    antar-dataset (mencegah data leakage), dan memetakan label standar:
    1 = phishing, 0 = legitimate.
    """
    df_phi = pd.read_csv(phi_path)
    df_legit = pd.read_csv(legit_path)

    df_phi["url_norm"] = df_phi["URL"].apply(normalize_url)
    df_legit["url_norm"] = df_legit["URL"].apply(normalize_url)

    df_phi = df_phi[df_phi["url_norm"] != ""].drop_duplicates(subset=["url_norm"]).copy()
    df_legit = df_legit[df_legit["url_norm"] != ""].drop_duplicates(subset=["url_norm"]).copy()

    # Hapus URL yang tumpang tindih dari dataset kedua
    df_legit = df_legit[~df_legit["url_norm"].isin(set(df_phi["url_norm"]))].copy()

    # Pada dataset mentah PhiUSIIL & LegitPhish: 0 = phishing, 1 = legitimate.
    # Dikonversi menjadi standar proyek: 1 = phishing, 0 = legitimate.
    df_phi["target"] = (df_phi["label"].astype(int) == 0).astype(int)
    df_legit["target"] = (df_legit["ClassLabel"].astype(int) == 0).astype(int)

    return df_phi, df_legit