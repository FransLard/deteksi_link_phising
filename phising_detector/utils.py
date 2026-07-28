import os
import sys
from pathlib import Path
import pandas as pd

PROJECT_DIR = Path(__file__).parent.parent
DATA_DIR = PROJECT_DIR / "data"
MODEL_DIR = PROJECT_DIR / "models"

def ensure_dirs():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

def download_uci_dataset():
    ensure_dirs()
    csv_path = DATA_DIR / "phishing_dataset.csv"

    if csv_path.exists():
        print(f"[OK] Dataset sudah ada di {csv_path}")
        return str(csv_path)

    print("[*] Mendownload dataset phishing dari UCI Machine Learning Repository...")
    try:
        from ucimlrepo import fetch_ucirepo
        phishing_data = fetch_ucirepo(id=327)

        X = phishing_data.data.features
        y = phishing_data.data.targets

        df = X.copy()
        df['Result'] = y.values

        df.to_csv(csv_path, index=False)
        print(f"[OK] Dataset berhasil disimpan: {csv_path} ({len(df)} baris)")
        return str(csv_path)

    except Exception as e:
        print(f"[!] Gagal download dataset dari UCI: {e}")
        print("[*] Membuat dataset sintetik untuk demonstrasi...")
        return _create_synthetic_dataset()

def _create_synthetic_dataset():
    import pandas as pd
    import numpy as np

    csv_path = DATA_DIR / "phishing_dataset.csv"
    print("[*] Membuat dataset sintetik untuk demonstrasi...")

    np.random.seed(42)
    n_samples = 2000

    data = {}
    feature_names = [
        'having_IP_Address', 'URL_Length', 'Shortining_Service',
        'having_At_Symbol', 'double_slash_redirecting', 'Prefix_Suffix',
        'having_Sub_Domain', 'SSLfinal_State', 'Domain_registeration_length',
        'port', 'HTTPS_token', 'Request_URL', 'URL_of_Anchor',
        'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL',
        'Redirect', 'on_mouseover', 'RightClick', 'popUpWindow',
        'Iframe', 'age_of_domain', 'DNSRecord', 'web_traffic',
        'Page_Rank', 'Google_Index', 'Links_pointing_to_page',
        'Statistical_report'
    ]

    for feat in feature_names:
        data[feat] = np.random.choice([-1, 0, 1], n_samples)

    result = []
    for i in range(n_samples):
        phishing_score = sum(1 for feat in feature_names if data[feat][i] == -1)
        legitimate_score = sum(1 for feat in feature_names if data[feat][i] == 1)

        if phishing_score > legitimate_score + 3:
            result.append(-1)
        elif legitimate_score > phishing_score + 3:
            result.append(1)
        else:
            result.append(0)

    df = pd.DataFrame(data)
    df['Result'] = result

    df.to_csv(csv_path, index=False)
    print(f"[OK] Dataset sintetik dibuat: {csv_path} ({n_samples} baris)")
    return str(csv_path)

def setup_models():
    from .model import PhishingModel

    ensure_dirs()
    model_path = MODEL_DIR / "phishing_model.pkl"

    if model_path.exists():
        print(f"[OK] Model sudah ada di {model_path}")
        return str(model_path)

    dataset_path = download_uci_dataset()

    print("[*] Melatih model Random Forest...")
    model = PhishingModel()
    result = model.train(dataset_path)

    saved_path = model.save("phishing_model.pkl")
    print(f"[OK] Model berhasil dilatih")
    print(f"    Akurasi: {result['accuracy']*100:.2f}%")
    print(f"    Dataset: {result['n_samples']} sampel")
    print(f"    Model:  {saved_path}")

    return saved_path

def print_banner():
    print("=" * 54)
    print("      PHISHING WEBSITE DETECTOR")
    print("   Mendeteksi Website Phishing dengan ML")
    print("=" * 54)

def print_feature_table():
    features = [
        ("having_IP_Address", "Menggunakan IP address", "Cek apakah host berupa IP"),
        ("URL_Length", "Panjang URL", "URL panjang >75 = mencurigakan"),
        ("Shortining_Service", "URL Shortener", "bit.ly, tinyurl, dll"),
        ("having_At_Symbol", "Simbol @", "Adanya @ dalam URL"),
        ("double_slash_redirecting", "Redirect //", "Redirect tambahan"),
        ("Prefix_Suffix", "Tanda - di domain", "Domain dengan strip"),
        ("having_Sub_Domain", "Subdomain", ">2 subdomain = mencurigakan"),
        ("SSLfinal_State", "HTTPS", "HTTPS valid/tidak"),
        ("age_of_domain", "Umur Domain", "Domain baru <6 bulan"),
        ("DNSRecord", "DNS Record", "Domain terdaftar/tidak"),
    ]

    print(f"\n{'Fitur':30} {'Deskripsi':20} {'Detail'}")
    print("-" * 70)
    for name, desc, detail in features:
        print(f"{name:30} {desc:20} {detail}")
    print()
