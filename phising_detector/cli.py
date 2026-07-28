import argparse
import sys
from pathlib import Path

from . import __version__
from .model import PhishingModel, map_prediction_label
from .analyzer import Analyzer
from .utils import (
    setup_models, print_banner, print_feature_table,
    download_uci_dataset, ensure_dirs
)
from .feature_extractor import FeatureExtractor

MODEL_DIR = Path(__file__).parent.parent / "models"
DATA_DIR = Path(__file__).parent.parent / "data"

def main():
    parser = argparse.ArgumentParser(
        prog='phising-detector',
        description='Phishing Website Detection Tool - Mendeteksi website phishing menggunakan Machine Learning',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh penggunaan:
  %(prog)s check https://example.com
  %(prog)s analyze https://example.com
  %(prog)s train
  %(prog)s train --dataset data/my_dataset.csv
  %(prog)s features
  %(prog)s setup
        """
    )

    parser.add_argument(
        '--version', action='version',
        version=f'%(prog)s {__version__}'
    )

    subparsers = parser.add_subparsers(dest='command', help='Perintah yang tersedia')

    parser_check = subparsers.add_parser('check', help='Deteksi cepat: phishing atau legitimate')
    parser_check.add_argument('url', help='URL website yang akan diperiksa')
    parser_check.add_argument('--model', default='phishing_model.pkl', help='Nama file model')

    parser_analyze = subparsers.add_parser('analyze', help='Deteksi dengan analisis detail')
    parser_analyze.add_argument('url', help='URL website yang akan diperiksa')
    parser_analyze.add_argument('--model', default='phishing_model.pkl', help='Nama file model')
    parser_analyze.add_argument('--verbose', '-v', action='store_true', help='Tampilkan semua fitur')

    parser_train = subparsers.add_parser('train', help='Latih model baru dengan dataset')
    parser_train.add_argument('--dataset', '-d', help='Path ke dataset CSV (opsional, default: download UCI dataset)')
    parser_train.add_argument('--output', '-o', default='phishing_model.pkl', help='Nama file output model')
    parser_train.add_argument('--test-size', type=float, default=0.2, help='Proporsi data testing (default: 0.2)')

    parser_features = subparsers.add_parser('features', help='Tampilkan daftar fitur yang digunakan')

    parser_setup = subparsers.add_parser('setup', help='Setup awal: download dataset & training model')

    args = parser.parse_args()

    if args.command is None:
        print_banner()
        parser.print_help()
        return

    if args.command == 'features':
        print_banner()
        print("Fitur yang digunakan untuk deteksi phishing:\n")
        print_feature_table()
        return

    if args.command == 'setup':
        print_banner()
        print("[*] Memulai setup...")
        ensure_dirs()
        setup_models()
        print("[OK] Setup selesai!")
        return

    if args.command == 'train':
        print_banner()
        print("[*] Memulai training model...")
        ensure_dirs()

        dataset_path = args.dataset
        if dataset_path is None:
            print("[*] Dataset tidak ditentukan, mendownload dataset default...")
            dataset_path = download_uci_dataset()

        model = PhishingModel()
        result = model.train(dataset_path, test_size=args.test_size)

        model_path = model.save(args.output)
        print(f"\n[OK] Training selesai!")
        print(f"    Akurasi      : {result['accuracy']*100:.2f}%")
        print(f"    Data Train   : {int(result['n_samples'] * (1 - result['test_size']))} samples")
        print(f"    Data Test    : {int(result['n_samples'] * result['test_size'])} samples")
        print(f"    Model        : {model_path}")

        print(f"\n   Feature Importance (Top 5):")
        for i, (name, importance) in enumerate(result['feature_importance'][:5], 1):
            print(f"   {i}. {name}: {importance:.4f}")
        return

    if args.command in ('check', 'analyze'):
        print_banner()
        model_path = MODEL_DIR / args.model

        if not model_path.exists():
            print(f"[!] Model tidak ditemukan di {model_path}")
            answer = input("[?] Jalankan setup untuk download dataset & training? (y/n): ")
            if answer.lower() == 'y':
                setup_models()
            else:
                print("[!] Jalankan 'python -m phising_detector setup' terlebih dahulu")
                sys.exit(1)

        print(f"[*] Memuat model...")
        model = PhishingModel()
        model.load(args.model)

        print(f"[*] Menganalisis URL: {args.url}\n")
        analyzer = Analyzer(model)
        result = analyzer.analyze(args.url)

        if args.command == 'check':
            label = result['label']
            confidence = result['confidence'] * 100
            print(f"  URL      : {result['url']}")
            print(f"  Status   : {label}")
            print(f"  Confidence: {confidence:.1f}%")
        else:
            analyzer.print_report(result, verbose=args.verbose)

        return

    parser.print_help()


if __name__ == '__main__':
    main()
