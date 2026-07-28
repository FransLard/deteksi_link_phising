import os
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
from pathlib import Path

MODEL_DIR = Path(__file__).parent.parent / "models"
DATASET_DIR = Path(__file__).parent.parent / "data"

FEATURE_NAMES = [
    'having_IP_Address', 'URL_Length', 'Shortining_Service',
    'having_At_Symbol', 'double_slash_redirecting', 'Prefix_Suffix',
    'having_Sub_Domain', 'SSLfinal_State',     'Domain_registeration_length',
    'favicon', 'port', 'HTTPS_token', 'Request_URL', 'URL_of_Anchor',
    'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL',
    'Redirect', 'on_mouseover', 'RightClick', 'popUpWindow',
    'Iframe', 'age_of_domain', 'DNSRecord', 'web_traffic',
    'Page_Rank', 'Google_Index', 'Links_pointing_to_page',
    'Statistical_report'
]

UCI_COLUMN_MAPPING = {
    'having_ip_address': 'having_IP_Address',
    'url_length': 'URL_Length',
    'shortining_service': 'Shortining_Service',
    'having_at_symbol': 'having_At_Symbol',
    'double_slash_redirecting': 'double_slash_redirecting',
    'prefix_suffix': 'Prefix_Suffix',
    'having_sub_domain': 'having_Sub_Domain',
    'sslfinal_state': 'SSLfinal_State',
    'domain_registration_length': 'Domain_registeration_length',
    'favicon': 'favicon',
    'port': 'port',
    'https_token': 'HTTPS_token',
    'request_url': 'Request_URL',
    'url_of_anchor': 'URL_of_Anchor',
    'links_in_tags': 'Links_in_tags',
    'sfh': 'SFH',
    'submitting_to_email': 'Submitting_to_email',
    'abnormal_url': 'Abnormal_URL',
    'redirect': 'Redirect',
    'on_mouseover': 'on_mouseover',
    'rightclick': 'RightClick',
    'popupwindow': 'popUpWindow',
    'iframe': 'Iframe',
    'age_of_domain': 'age_of_domain',
    'dnsrecord': 'DNSRecord',
    'web_traffic': 'web_traffic',
    'page_rank': 'Page_Rank',
    'google_index': 'Google_Index',
    'links_pointing_to_page': 'Links_pointing_to_page',
    'statistical_report': 'Statistical_report',
}

TARGET_COLUMN = 'Result'
TARGET_ALIASES = ['result', 'Result', 'class', 'Class']

class PhishingModel:
    def __init__(self):
        self.model = None
        self.feature_importance = None
        self.feature_cols = None

    def _resolve_columns(self, df):
        df_columns = [c.strip() for c in df.columns]
        df.columns = df_columns

        target_col = None
        for alias in TARGET_ALIASES:
            if alias in df.columns:
                target_col = alias
                break

        rename_map = {}
        for uci_name, my_name in UCI_COLUMN_MAPPING.items():
            if uci_name in df.columns:
                rename_map[uci_name] = my_name

        df = df.rename(columns=rename_map)

        feature_cols = []
        for my_name in FEATURE_NAMES:
            if my_name in df.columns:
                feature_cols.append(my_name)
            elif my_name.lower() in df.columns:
                feature_cols.append(my_name.lower())

        if not feature_cols:
            available = [c for c in df.columns]
            print(f"Kolom tersedia: {available}")
            raise ValueError("Tidak dapat menemukan kolom fitur yang sesuai di dataset.")

        return df, feature_cols, target_col

    def train(self, dataset_path=None, test_size=0.2, random_state=42):
        if dataset_path is None:
            dataset_path = DATASET_DIR / "phishing_dataset.csv"

        if not os.path.exists(dataset_path):
            raise FileNotFoundError(f"Dataset tidak ditemukan di {dataset_path}")

        df = pd.read_csv(dataset_path)
        df, feature_cols, target_col = self._resolve_columns(df)

        if target_col is None:
            print(f"Kolom tersedia: {list(df.columns)}")
            raise ValueError(f"Kolom target tidak ditemukan. Cari salah satu dari: {TARGET_ALIASES}")

        X = df[feature_cols].fillna(0)
        y = df[target_col].fillna(0)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )

        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=random_state,
            n_jobs=-1
        )
        self.model.fit(X_train, y_train)
        self.feature_cols = feature_cols

        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)

        self.feature_importance = sorted(
            zip(feature_cols, self.model.feature_importances_),
            key=lambda x: x[1],
            reverse=True
        )

        report = classification_report(y_test, y_pred, output_dict=True)

        cm = confusion_matrix(y_test, y_pred)

        return {
            'accuracy': accuracy,
            'classification_report': report,
            'confusion_matrix': cm,
            'feature_importance': self.feature_importance,
            'test_size': test_size,
            'n_samples': len(df)
        }

    def predict(self, feature_vector):
        if self.model is None:
            raise ValueError("Model belum di-train. Jalankan train() terlebih dahulu.")

        cols = self.feature_cols if self.feature_cols else FEATURE_NAMES
        features_df = pd.DataFrame([feature_vector], columns=cols)
        features_df = features_df.fillna(0)
        prediction = self.model.predict(features_df)[0]
        probabilities = self.model.predict_proba(features_df)[0]

        return int(prediction), probabilities

    def predict_proba(self, feature_vector):
        if self.model is None:
            raise ValueError("Model belum di-train. Jalankan train() terlebih dahulu.")

        cols = self.feature_cols if self.feature_cols else FEATURE_NAMES
        features_df = pd.DataFrame([feature_vector], columns=cols)
        features_df = features_df.fillna(0)
        return self.model.predict_proba(features_df)[0]

    def save(self, filename="phishing_model.pkl"):
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        path = MODEL_DIR / filename
        joblib.dump(self.model, path)
        return str(path)

    def load(self, filename="phishing_model.pkl"):
        path = MODEL_DIR / filename
        if not os.path.exists(path):
            raise FileNotFoundError(f"Model tidak ditemukan di {path}")
        self.model = joblib.load(path)
        return self

    def is_trained(self):
        return self.model is not None

    @staticmethod
    def get_available_datasets():
        if not DATASET_DIR.exists():
            return []
        return [f.name for f in DATASET_DIR.iterdir() if f.suffix == '.csv']

def map_prediction_label(value):
    if value == 1 or value == '1':
        return "LEGITIMATE"
    elif value == -1 or value == '-1':
        return "PHISHING"
    elif value == 0 or value == '0':
        return "SUSPICIOUS"
    return "UNKNOWN"

def map_label_color(label):
    if label == "LEGITIMATE":
        return "green"
    elif label == "PHISHING":
        return "red"
    elif label == "SUSPICIOUS":
        return "yellow"
    return "white"
