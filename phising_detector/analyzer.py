from .feature_extractor import FeatureExtractor
from .model import PhishingModel, map_prediction_label

RISK_FEATURES_PHISHING = [
    'having_IP_Address', 'Shortining_Service', 'having_At_Symbol',
    'double_slash_redirecting', 'Prefix_Suffix', 'HTTPS_token',
    'Submitting_to_email', 'on_mouseover', 'RightClick'
]

HIGH_IMPACT_FEATURES = [
    'SSLfinal_State', 'age_of_domain', 'DNSRecord',
    'having_Sub_Domain', 'URL_Length'
]

class Analyzer:
    def __init__(self, model: PhishingModel):
        self.model = model
        self.extractor = FeatureExtractor()

    def analyze(self, url):
        features = self.extractor.extract_all(url)
        feature_vector = [features[name] for name in FeatureExtractor.FEATURE_NAMES]

        prediction, probabilities = self.model.predict(feature_vector)
        label = map_prediction_label(prediction)

        phishing_prob = 0
        legitimate_prob = 0
        if len(probabilities) == 2:
            if prediction == -1:
                phishing_prob = probabilities[1] if len(probabilities) > 1 else probabilities[0]
                legitimate_prob = probabilities[0]
            elif prediction == 1:
                legitimate_prob = probabilities[1] if len(probabilities) > 1 else probabilities[0]
                phishing_prob = probabilities[0]
            else:
                phishing_prob = probabilities[0]
                legitimate_prob = probabilities[1] if len(probabilities) > 1 else 0

        suspicious_features = []
        safe_features = []
        neutral_features = []

        for name, value in features.items():
            if value == -1:
                suspicious_features.append({
                    'name': name,
                    'description': FeatureExtractor.feature_description(name),
                    'explanation': FeatureExtractor.value_explanation(name, value),
                    'is_high_risk': name in RISK_FEATURES_PHISHING or name in HIGH_IMPACT_FEATURES
                })
            elif value == 1:
                safe_features.append({
                    'name': name,
                    'description': FeatureExtractor.feature_description(name),
                    'explanation': FeatureExtractor.value_explanation(name, value)
                })
            else:
                neutral_features.append({
                    'name': name,
                    'description': FeatureExtractor.feature_description(name),
                    'explanation': FeatureExtractor.value_explanation(name, value)
                })

        total_checks = len(features)
        suspicious_count = len(suspicious_features)
        safe_count = len(safe_features)

        risk_score = suspicious_count / total_checks * 100

        top_reasons = sorted(
            suspicious_features,
            key=lambda x: (x.get('is_high_risk', False), x['name']),
            reverse=True
        )[:5]

        result = {
            'url': url,
            'prediction': prediction,
            'label': label,
            'confidence': max(probabilities) if len(probabilities) > 0 else 0,
            'phishing_probability': phishing_prob,
            'legitimate_probability': legitimate_prob,
            'risk_score': risk_score,
            'total_features': total_checks,
            'suspicious_count': suspicious_count,
            'safe_count': safe_count,
            'suspicious_features': suspicious_features,
            'safe_features': safe_features,
            'neutral_features': neutral_features,
            'top_reasons': top_reasons,
            'all_features': features
        }

        return result

    def print_report(self, result, verbose=False):
        print("=" * 70)
        print("                   PHISHING DETECTION REPORT")
        print("=" * 70)
        print(f"\nURL              : {result['url']}")
        print(f"Status           : {result['label']}")
        print(f"Risk Score       : {result['risk_score']:.1f}%")
        print(f"Confidence       : {result['confidence']*100:.1f}%")
        print(f"Phishing Prob    : {result['phishing_probability']*100:.1f}%")
        print(f"Legitimate Prob  : {result['legitimate_probability']*100:.1f}%")

        print(f"\n--- Ringkasan ---")
        print(f"Total fitur dicek        : {result['total_features']}")
        print(f"Fitur mencurigakan       : {result['suspicious_count']}")
        print(f"Fitur aman               : {result['safe_count']}")

        if result['top_reasons']:
            print(f"\n--- Alasan Utama ---")
            for i, reason in enumerate(result['top_reasons'], 1):
                risk_tag = " [HIGH RISK]" if reason.get('is_high_risk') else ""
                print(f"{i}. {reason['description']}: {reason['explanation']}{risk_tag}")

        if verbose and result['suspicious_features']:
            print(f"\n--- Semua Fitur Mencurigakan ---")
            for feat in result['suspicious_features']:
                risk_tag = " [HIGH RISK]" if feat.get('is_high_risk') else ""
                print(f"  - {feat['description']}: {feat['explanation']}{risk_tag}")

        if verbose and result['safe_features']:
            print(f"\n--- Fitur Aman ---")
            for feat in result['safe_features']:
                print(f"  - {feat['description']}: {feat['explanation']}")

        print("\n" + "=" * 70)
