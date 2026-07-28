# Phishing Website Detector

Deteksi website phishing menggunakan **Machine Learning** (Random Forest) dengan ekstraksi 30 fitur dari URL dan konten halaman web.

## Fitur

- **Deteksi Cepat**: Input URL, langsung dapat hasil phishing/legitimate
- **Analisis Detail**: Penjelasan mengapa URL dikategorikan phishing
- **30 Fitur Ekstraksi**: IP address, panjang URL, SSL, subdomain, umur domain, dll.
- **Training Model**: Latih ulang dengan dataset sendiri

## Cara Install

```bash
pip install -r requirements.txt
python -m phising_detector setup
```

## Cara Penggunaan

```bash
# Deteksi cepat
python -m phising_detector check https://example.com

# Analisis detail
python -m phising_detector analyze https://example.com
python -m phising_detector analyze https://example.com --verbose

# Latih ulang model
python -m phising_detector train --dataset dataset.csv

# Lihat daftar fitur
python -m phising_detector features
```

## Contoh Output

```
======================================================
      PHISHING WEBSITE DETECTOR
   Mendeteksi Website Phishing dengan ML
======================================================

URL              : https://www.google.com
Status           : LEGITIMATE
Risk Score       : 3.3%
Confidence       : 83.0%

--- Ringkasan ---
Total fitur dicek        : 30
Fitur mencurigakan       : 1
Fitur aman               : 19

--- Alasan Utama ---
1. Proporsi resource dari domain lain: Banyak resource eksternal
```

## Struktur Proyek

```
Deteksi-Phising/
  phising_detector/
    __init__.py         # Versi package
    __main__.py         # Entry point
    cli.py              # CLI dengan argparse
    feature_extractor.py # Ekstraksi 30 fitur dari URL
    model.py            # Random Forest Classifier
    analyzer.py         # Analisis hasil deteksi
    utils.py            # Download dataset & utility
  data/
    phishing_dataset.csv # Dataset UCI (11055 sampel)
  models/
    phishing_model.pkl   # Model terlatih
  requirements.txt
  README.md
```

## Dataset

Menggunakan **UCI Phishing Websites Dataset** (11055 sampel, 30 fitur).
Dataset otomatis di-download saat `python -m phising_detector setup`.

## Model

- **Algorithm**: Random Forest Classifier
- **Akurasi**: ~96.7%
- **Fitur**: 30 fitur ekstraksi URL & halaman web
- **Framework**: scikit-learn
