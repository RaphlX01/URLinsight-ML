# Dokumentasi Feature Schema, Evaluasi Model & Contoh Uji API (v1.0.0)

## 1. Skema Fitur Final (12 Fitur) & Aturan Severity
Model `rf_v1.0.0.joblib` mengekstrak 12 fitur secara langsung dari teks URL yang telah dinormalisasi:

| No | Nama Fitur | Tipe | Makna | Aturan Severity |
|---|---|---|---|---|
| 1 | `url_length` | integer | Panjang total karakter URL | `high` (> 75), `medium` (> 50), `info` (<= 50) |
| 2 | `dot_count` | integer | Jumlah karakter titik (`.`) | `medium` (> 3), `info` (<= 3) |
| 3 | `digit_count` | integer | Jumlah karakter angka (`0-9`) | `medium` (> 5), `info` (<= 5) |
| 4 | `uses_https` | boolean | Penggunaan protokol `https://` | `info` (`true`), `medium` (`false`) |
| 5 | `domain_length` | integer | Panjang karakter hostname/domain | `medium` (> 30), `info` (<= 30) |
| 6 | `url_entropy` | float | Keacakan susunan karakter (Shannon Entropy) | `medium` (> 4.3), `info` (<= 4.3) |
| 7 | `hostname_is_ip` | boolean | Hostname berupa alamat IP langsung | `high` (`true`), `info` (`false`) |
| 8 | `subdomain_count` | integer | Jumlah tingkat subdomain | `high` (>= 3), `medium` (2), `info` (<= 1) |
| 9 | `has_hyphen_in_domain` | boolean | Keberadaan tanda hubung (`-`) pada domain | `low` (`true`), `info` (`false`) |
| 10 | `special_char_count` | integer | Jumlah karakter `@`, `?`, `=`, `&`, `%` | `medium` (>= 3), `info` (< 3) |
| 11 | `suspicious_keyword_count` | integer | Jumlah kata kunci umpan (`login`, `verify`, `bca`, dll.) | `high` (>= 2), `medium` (1), `info` (0) |
| 12 | `has_risky_tld` | boolean | Penggunaan TLD berisiko tinggi (`.xyz`, `.tk`, `.top`, dll.) | `high` (`true`), `info` (`false`) |

## 2. Ringkasan Evaluasi Model Final (`v1.0.0`)
- **Algoritma:** Random Forest (`n_estimators=150`, `max_depth=24`, `random_state=42`)
- **Dataset:** Gabungan bersih PhiUSIIL + LegitPhish (bebas duplikat & bebas URL tumpang tindih)
- **Accuracy:** `97.27%` (`0.9727`)
- **Precision (Phishing):** `98.59%` (`0.9859`)
- **Recall (Phishing):** `96.38%` (`0.9638`)
- **F1-Score (Phishing):** `97.47%` (`0.9747`)
- **Confusion Matrix:** `TP = 31.352` | `FP = 448` | `TN = 26.608` | `FN = 1.178`

## 3. Contoh URL Uji Referensi (Untuk Backend & Demo)

| No | Input URL | Ekspektasi Prediksi | Catatan Pengujian |
|---|---|---|---|
| 1 | `http://192.168.1.1/secure/login-verify.php?id=12345` | `phishing` | Alamat IP langsung + kata kunci sensitif + HTTP |
| 2 | `http://bca-login-palsu.xyz` | `phishing` | Kata umpan perbankan + TLD berisiko `.xyz` |
| 3 | `https://metamsk01lgiix.godaddysites.com/` | `phishing` | Sampel phishing nyata dari dataset LegitPhish |
| 4 | `http://secure-update-account.top/verify?user=99182` | `phishing` | Subdomain/domain tanda hubung + TLD `.top` + query |
| 5 | `http://paypal-confirm-billing.tk/login` | `phishing` | Impersonasi merek + TLD `.tk` + kata umpan |
| 6 | `https://www.southbankmosaics.com` | `legitimate` | Sampel aman nyata dari dataset PhiUSIIL |
| 7 | `https://www.uni-mainz.de` | `legitimate` | Domain institusi akademik resmi dengan HTTPS |
| 8 | `https://www.bca.co.id` | `legitimate` | Domain resmi perbankan Indonesia |
| 9 | `https://github.com/fastapi/fastapi` | `legitimate` | URL repositori dengan path normal & HTTPS |
| 10 | `""` (string kosong / spasi) | Error `422` (`INVALID_URL`) | Validasi penolakan input tidak valid |
