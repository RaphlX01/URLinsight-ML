import math
import re
from collections import Counter
from urllib.parse import urlparse

FEATURE_ORDER = [
    "url_length",
    "dot_count",
    "digit_count",
    "uses_https",
    "domain_length",
    "url_entropy",
    "hostname_is_ip",
    "subdomain_count",
    "has_hyphen_in_domain",
    "special_char_count",
    "suspicious_keyword_count",
    "has_risky_tld",
]

FEATURE_DESCRIPTIONS = {
    "url_length": "Panjang total karakter URL",
    "dot_count": "Jumlah karakter titik (.) pada URL",
    "digit_count": "Jumlah karakter angka (0-9) pada URL",
    "uses_https": "Penggunaan protokol aman HTTPS",
    "domain_length": "Panjang karakter nama domain/host",
    "url_entropy": "Tingkat keacakan susunan karakter URL (Shannon Entropy)",
    "hostname_is_ip": "Penggunaan alamat IP langsung sebagai hostname",
    "subdomain_count": "Jumlah tingkat subdomain",
    "has_hyphen_in_domain": "Keberadaan tanda hubung (-) pada domain",
    "special_char_count": "Jumlah karakter khusus (@, ?, =, &, %)",
    "suspicious_keyword_count": "Jumlah kata kunci umpan/sensitif pada URL",
    "has_risky_tld": "Penggunaan ekstensi domain (TLD) berisiko tinggi",
}

SUSPICIOUS_KEYWORDS = (
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "banking", "password", "credential", "wallet", "bca", "bri", "mandiri",
    "bni", "dana", "ovo", "gopay", "paypal", "admin", "auth"
)

RISKY_TLDS = (
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".icu",
    ".buzz", ".club", ".online", ".site", ".website", ".info", ".vip"
)


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    return -sum((count / n) * math.log2(count / n) for count in Counter(text).values())


def extract_features_vector(normalized_url: str) -> list:
    """Mengembalikan vektor 12 fitur dengan urutan tetap (FEATURE_ORDER)."""
    parsed = urlparse(normalized_url)
    host = parsed.hostname or ""
    url_lower = normalized_url.lower()

    url_length = len(normalized_url)
    dot_count = normalized_url.count(".")
    digit_count = sum(ch.isdigit() for ch in normalized_url)
    uses_https = 1 if parsed.scheme == "https" else 0
    domain_length = len(host)
    url_entropy = round(shannon_entropy(normalized_url), 6)
    hostname_is_ip = 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host) else 0
    subdomain_count = max(0, host.count(".") - 1) if not hostname_is_ip else 0
    has_hyphen_in_domain = 1 if "-" in host else 0
    special_char_count = sum(normalized_url.count(c) for c in ("@", "?", "=", "&", "%"))
    suspicious_keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    has_risky_tld = 1 if any(host.endswith(tld) for tld in RISKY_TLDS) else 0

    return [
        url_length,
        dot_count,
        digit_count,
        uses_https,
        domain_length,
        url_entropy,
        hostname_is_ip,
        subdomain_count,
        has_hyphen_in_domain,
        special_char_count,
        suspicious_keyword_count,
        has_risky_tld,
    ]


def build_indicators(normalized_url: str) -> tuple[list, list[dict]]:
    """
    Mengekstrak vektor fitur sekaligus menyusun daftar indicators
    sesuai spesifikasi kontrak JSON (name, value, description, interpretation, severity).
    """
    vec = extract_features_vector(normalized_url)
    f = dict(zip(FEATURE_ORDER, vec))

    rules = {
        "url_length": (
            f["url_length"],
            "URL sangat panjang (> 75 karakter)" if f["url_length"] > 75
            else ("URL relatif panjang (> 50 karakter)" if f["url_length"] > 50 else "Panjang URL normal"),
            "high" if f["url_length"] > 75 else ("medium" if f["url_length"] > 50 else "info"),
        ),
        "dot_count": (
            f["dot_count"],
            "Jumlah titik berlebih pada struktur URL" if f["dot_count"] > 3 else "Jumlah titik normal",
            "medium" if f["dot_count"] > 3 else "info",
        ),
        "digit_count": (
            f["digit_count"],
            "Terdapat banyak karakter angka pada URL" if f["digit_count"] > 5 else "Jumlah karakter angka rendah",
            "medium" if f["digit_count"] > 5 else "info",
        ),
        "uses_https": (
            bool(f["uses_https"]),
            "URL menggunakan enkripsi HTTPS" if f["uses_https"] else "URL tidak menggunakan HTTPS (HTTP polos)",
            "info" if f["uses_https"] else "medium",
        ),
        "domain_length": (
            f["domain_length"],
            "Nama domain sangat panjang" if f["domain_length"] > 30 else "Panjang domain normal",
            "medium" if f["domain_length"] > 30 else "info",
        ),
        "url_entropy": (
            round(f["url_entropy"], 4),
            "Keacakan karakter URL tinggi (indikasi string acak/obfuscation)" if f["url_entropy"] > 4.3 else "Keacakan karakter normal",
            "medium" if f["url_entropy"] > 4.3 else "info",
        ),
        "hostname_is_ip": (
            bool(f["hostname_is_ip"]),
            "Hostname menggunakan alamat IP langsung (sangat mencurigakan)" if f["hostname_is_ip"] else "Hostname menggunakan nama domain",
            "high" if f["hostname_is_ip"] else "info",
        ),
        "subdomain_count": (
            f["subdomain_count"],
            "Terdapat banyak subdomain bertingkat" if f["subdomain_count"] >= 2 else "Jumlah subdomain normal",
            "high" if f["subdomain_count"] >= 3 else ("medium" if f["subdomain_count"] == 2 else "info"),
        ),
        "has_hyphen_in_domain": (
            bool(f["has_hyphen_in_domain"]),
            "Terdapat tanda hubung (-) pada nama domain" if f["has_hyphen_in_domain"] else "Tidak ada tanda hubung pada domain",
            "low" if f["has_hyphen_in_domain"] else "info",
        ),
        "special_char_count": (
            f["special_char_count"],
            "Terdapat beberapa karakter khusus/parameter query" if f["special_char_count"] >= 3 else "Karakter khusus minimal",
            "medium" if f["special_char_count"] >= 3 else "info",
        ),
        "suspicious_keyword_count": (
            f["suspicious_keyword_count"],
            f"Terdeteksi {f['suspicious_keyword_count']} kata kunci sensitif/umpan" if f["suspicious_keyword_count"] > 0 else "Tidak ditemukan kata kunci umpan",
            "high" if f["suspicious_keyword_count"] >= 2 else ("medium" if f["suspicious_keyword_count"] == 1 else "info"),
        ),
        "has_risky_tld": (
            bool(f["has_risky_tld"]),
            "Menggunakan ekstensi TLD berisiko tinggi" if f["has_risky_tld"] else "Menggunakan ekstensi TLD umum",
            "high" if f["has_risky_tld"] else "info",
        ),
    }

    indicators = []
    for name in FEATURE_ORDER:
        val, interp, sev = rules[name]
        indicators.append({
            "name": name,
            "value": val,
            "description": FEATURE_DESCRIPTIONS[name],
            "interpretation": interp,
            "severity": sev,
        })

    return vec, indicators