import threading
import sys
import os
from pathlib import Path
import customtkinter as ctk
from tkinter import messagebox

sys.path.insert(0, str(Path(__file__).parent.parent))

from phising_detector.model import PhishingModel, map_prediction_label
from phising_detector.analyzer import Analyzer
from phising_detector.utils import ensure_dirs, setup_models, MODEL_DIR
from phising_detector.feature_extractor import FeatureExtractor

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

MODEL_PATH = MODEL_DIR / "phishing_model.pkl"

class PhishingDetectorGUI:
    def __init__(self):
        self.model = None
        self.analyzer = None

        self.window = ctk.CTk()
        self.window.title("Phishing Website Detector")
        self.window.geometry("700x680")
        self.window.minsize(600, 550)

        self.window.grid_columnconfigure(0, weight=1)
        self.window.grid_rowconfigure(0, weight=0)
        self.window.grid_rowconfigure(1, weight=1)

        self._build_header()
        self._build_input_area()
        self._build_result_area()
        self._build_status_bar()

        self._load_model_async()

    def _build_header(self):
        header = ctk.CTkFrame(self.window, corner_radius=0, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=(15, 5))
        header.grid_columnconfigure(0, weight=1)

        title = ctk.CTkLabel(
            header, text="PHISHING WEBSITE DETECTOR",
            font=ctk.CTkFont(size=22, weight="bold")
        )
        title.grid(row=0, column=0, pady=(0, 2))

        subtitle = ctk.CTkLabel(
            header, text="Machine Learning-based Phishing Detection",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        subtitle.grid(row=1, column=0, pady=(0, 5))

        self.theme_btn = ctk.CTkButton(
            header, text="Light Mode", width=90, height=28,
            command=self._toggle_theme, font=ctk.CTkFont(size=11)
        )
        self.theme_btn.grid(row=0, column=1, rowspan=2, padx=(0, 5), sticky="ne")

    def _build_input_area(self):
        input_frame = ctk.CTkFrame(self.window, corner_radius=10)
        input_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=5)
        input_frame.grid_columnconfigure(0, weight=1)

        self.url_entry = ctk.CTkEntry(
            input_frame, placeholder_text="Masukkan URL website... (contoh: https://example.com)",
            font=ctk.CTkFont(size=13), height=38
        )
        self.url_entry.grid(row=0, column=0, sticky="ew", padx=(15, 5), pady=(12, 4))
        self.url_entry.bind("<Return>", lambda e: self._check())

        btn_frame = ctk.CTkFrame(input_frame, fg_color="transparent")
        btn_frame.grid(row=1, column=0, sticky="ew", padx=15, pady=(0, 12))
        btn_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.check_btn = ctk.CTkButton(
            btn_frame, text="  Check", command=self._check,
            font=ctk.CTkFont(size=13), height=34, fg_color="#2b7a4b",
            hover_color="#1e5f38"
        )
        self.check_btn.grid(row=0, column=0, padx=3, sticky="ew")

        self.analyze_btn = ctk.CTkButton(
            btn_frame, text="  Analyze", command=self._analyze,
            font=ctk.CTkFont(size=13), height=34, fg_color="#1f538d",
            hover_color="#153e6b"
        )
        self.analyze_btn.grid(row=0, column=1, padx=3, sticky="ew")

        self.clear_btn = ctk.CTkButton(
            btn_frame, text="  Clear", command=self._clear,
            font=ctk.CTkFont(size=13), height=34, fg_color="#555555",
            hover_color="#444444"
        )
        self.clear_btn.grid(row=0, column=2, padx=3, sticky="ew")

        self.paste_btn = ctk.CTkButton(
            btn_frame, text="  Paste", command=self._paste,
            font=ctk.CTkFont(size=13), height=34, fg_color="#555555",
            hover_color="#444444"
        )
        self.paste_btn.grid(row=0, column=3, padx=3, sticky="ew")

    def _build_result_area(self):
        self.result_frame = ctk.CTkScrollableFrame(self.window, corner_radius=10)
        self.result_frame.grid(row=2, column=0, sticky="nsew", padx=20, pady=5)
        self.result_frame.grid_columnconfigure(0, weight=1)
        self.window.grid_rowconfigure(2, weight=1)

        self.status_label = ctk.CTkLabel(
            self.result_frame, text="",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.status_label.grid(row=0, column=0, pady=5)

        self.progress = ctk.CTkProgressBar(self.result_frame, mode="indeterminate")
        self.progress.grid(row=1, column=0, sticky="ew", padx=20, pady=5)
        self.progress.grid_remove()

        self.result_text = ctk.CTkTextbox(
            self.result_frame, wrap="word", font=ctk.CTkFont(size=12),
            height=200, state="disabled"
        )
        self.result_text.grid(row=2, column=0, sticky="nsew", padx=10, pady=5)

        self.features_frame = ctk.CTkFrame(self.result_frame, fg_color="transparent")
        self.features_frame.grid(row=3, column=0, sticky="ew", padx=5, pady=5)
        self.features_frame.grid_columnconfigure(1, weight=1)

        self.info_label = ctk.CTkLabel(
            self.result_frame, text="",
            font=ctk.CTkFont(size=11), text_color="gray"
        )
        self.info_label.grid(row=4, column=0, pady=5)

    def _build_status_bar(self):
        status_bar = ctk.CTkFrame(self.window, corner_radius=0, height=28, fg_color="transparent")
        status_bar.grid(row=3, column=0, sticky="ew", padx=20, pady=(2, 8))
        status_bar.grid_columnconfigure(0, weight=1)

        self.model_status = ctk.CTkLabel(
            status_bar, text="Memuat model...",
            font=ctk.CTkFont(size=11), text_color="gray"
        )
        self.model_status.grid(row=0, column=0, sticky="w")

    def _toggle_theme(self):
        current = ctk.get_appearance_mode()
        if current == "Dark":
            ctk.set_appearance_mode("Light")
            self.theme_btn.configure(text="Dark Mode")
        else:
            ctk.set_appearance_mode("Dark")
            self.theme_btn.configure(text="Light Mode")

    def _load_model_async(self):
        thread = threading.Thread(target=self._load_model, daemon=True)
        thread.start()

    def _load_model(self):
        try:
            if MODEL_PATH.exists():
                self.model = PhishingModel()
                self.model.load(str(MODEL_PATH))
                self.analyzer = Analyzer(self.model)
                self.window.after(0, lambda: self.model_status.configure(
                    text="Model siap | Akurasi: ~96.7% | Dataset: UCI Phishing (11055 sampel)",
                    text_color="green"
                ))
            else:
                self.window.after(0, lambda: self._prompt_setup())
        except Exception as e:
            self.window.after(0, lambda: self.model_status.configure(
                text=f"Error: {e}", text_color="red"
            ))

    def _prompt_setup(self):
        answer = messagebox.askyesno(
            "Model Tidak Ditemukan",
            "Model belum di-train. Jalankan setup sekarang?\n(Diperlukan koneksi internet)"
        )
        if answer:
            self.model_status.configure(text="Setup sedang berjalan...")
            thread = threading.Thread(target=self._run_setup, daemon=True)
            thread.start()
        else:
            self.model_status.configure(text="Model tidak tersedia", text_color="red")
            self.check_btn.configure(state="disabled")
            self.analyze_btn.configure(state="disabled")

    def _run_setup(self):
        try:
            ensure_dirs()
            setup_models()
            self.model = PhishingModel()
            self.model.load(str(MODEL_PATH))
            self.analyzer = Analyzer(self.model)
            self.window.after(0, lambda: self.model_status.configure(
                text="Model siap | Akurasi: ~96.7%", text_color="green"
            ))
            self.window.after(0, lambda: (
                self.check_btn.configure(state="normal"),
                self.analyze_btn.configure(state="normal")
            ))
        except Exception as e:
            self.window.after(0, lambda: self.model_status.configure(
                text=f"Setup gagal: {e}", text_color="red"
            ))

    def _check(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Input Kosong", "Silakan masukkan URL terlebih dahulu.")
            return
        if self.model is None or self.analyzer is None:
            messagebox.showerror("Model Error", "Model belum siap. Tunggu atau jalankan setup.")
            return
        self._run_detection(url, verbose=False)

    def _analyze(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Input Kosong", "Silakan masukkan URL terlebih dahulu.")
            return
        if self.model is None or self.analyzer is None:
            messagebox.showerror("Model Error", "Model belum siap. Tunggu atau jalankan setup.")
            return
        self._run_detection(url, verbose=True)

    def _run_detection(self, url, verbose=False):
        self._set_loading(True)
        thread = threading.Thread(
            target=self._detect_thread, args=(url, verbose), daemon=True
        )
        thread.start()

    def _detect_thread(self, url, verbose):
        try:
            result = self.analyzer.analyze(url)
            self.window.after(0, lambda: self._display_result(result, verbose))
        except Exception as e:
            self.window.after(0, lambda: self._show_error(str(e)))
        finally:
            self.window.after(0, lambda: self._set_loading(False))

    def _display_result(self, result, verbose):
        self.result_frame.grid(row=2, column=0, sticky="nsew", padx=20, pady=5)
        self._clear_result_display()

        label = result['label']
        confidence = result['confidence'] * 100
        risk = result['risk_score']

        if label == "LEGITIMATE":
            status_color = "#2b7a4b"
            emoji = "✓"
        elif label == "PHISHING":
            status_color = "#b33a3a"
            emoji = "✗"
        else:
            status_color = "#b58a2b"
            emoji = "?"

        self.status_label.configure(
            text=f"{emoji} {label}  |  Confidence: {confidence:.1f}%  |  Risk Score: {risk:.1f}%",
            text_color=status_color
        )

        self.result_text.configure(state="normal")
        self.result_text.delete("1.0", "end")

        self.result_text.insert("end", "   DETAIL ANALISIS\n", "title")
        self.result_text.insert("end", f"   URL: {result['url']}\n\n")
        self.result_text.insert("end", f"   Phishing Probability : {result['phishing_probability']*100:.1f}%\n")
        self.result_text.insert("end", f"   Legitimate Probability: {result['legitimate_probability']*100:.1f}%\n\n")
        self.result_text.insert("end", f"   Total Fitur Dicek     : {result['total_features']}\n")
        self.result_text.insert("end", f"   Fitur Mencurigakan    : {result['suspicious_count']}\n")
        self.result_text.insert("end", f"   Fitur Aman            : {result['safe_count']}\n\n")

        if result['top_reasons']:
            self.result_text.insert("end", "   ALASAN UTAMA\n", "title")
            for i, reason in enumerate(result['top_reasons'], 1):
                risk_tag = " [HIGH]" if reason.get('is_high_risk') else ""
                self.result_text.insert(
                    "end", f"   {i}. {reason['description']}: {reason['explanation']}{risk_tag}\n"
                )

        if verbose and result['suspicious_features']:
            self.result_text.insert("end", "\n   SEMUA FITUR MENCURIGAKAN\n", "title")
            for feat in result['suspicious_features']:
                risk_tag = " [HIGH]" if feat.get('is_high_risk') else ""
                self.result_text.insert(
                    "end", f"   - {feat['description']}: {feat['explanation']}{risk_tag}\n"
                )

        if verbose and result['safe_features']:
            self.result_text.insert("end", "\n   FITUR AMAN\n", "title")
            for feat in result['safe_features']:
                self.result_text.insert(
                    "end", f"   - {feat['description']}: {feat['explanation']}\n"
                )

        self.result_text.configure(state="disabled")

        self._build_feature_bars(result)

        self.info_label.configure(
            text=f"Analisis selesai | {result['total_features']} fitur dianalisis",
            text_color="gray"
        )

    def _build_feature_bars(self, result):
        for w in self.features_frame.winfo_children():
            w.destroy()

        ctk.CTkLabel(
            self.features_frame, text="RISK FACTORS",
            font=ctk.CTkFont(size=12, weight="bold")
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(5, 2))

        features = result['suspicious_features'] + result['safe_features']
        features = features[:8]

        for i, feat in enumerate(features):
            row = i + 1
            is_risk = feat in result['suspicious_features']
            bar_color = "#b33a3a" if is_risk else "#2b7a4b"

            label = ctk.CTkLabel(
                self.features_frame, text=feat['description'][:30],
                font=ctk.CTkFont(size=10), anchor="w", width=200
            )
            label.grid(row=row, column=0, sticky="w", padx=(0, 5), pady=1)

            bar_frame = ctk.CTkFrame(
                self.features_frame, height=14, width=150,
                fg_color="#333333" if ctk.get_appearance_mode() == "Dark" else "#dddddd"
            )
            bar_frame.grid(row=row, column=1, sticky="w", padx=5)
            bar_frame.grid_propagate(False)

            bar = ctk.CTkFrame(bar_frame, height=14, width=140, fg_color=bar_color)
            bar.place(relx=0, rely=0, relwidth=1, relheight=1)

            val_label = ctk.CTkLabel(
                self.features_frame, text=feat['explanation'],
                font=ctk.CTkFont(size=10), text_color="gray"
            )
            val_label.grid(row=row, column=2, sticky="w", padx=(5, 0), pady=1)

    def _clear_result_display(self):
        self.status_label.configure(text="")
        self.result_text.configure(state="normal")
        self.result_text.delete("1.0", "end")
        self.result_text.configure(state="disabled")
        self.info_label.configure(text="")
        for w in self.features_frame.winfo_children():
            w.destroy()

    def _set_loading(self, loading):
        if loading:
            self.progress.grid()
            self.progress.start()
            self.check_btn.configure(state="disabled")
            self.analyze_btn.configure(state="disabled")
        else:
            self.progress.stop()
            self.progress.grid_remove()
            self.check_btn.configure(state="normal")
            self.analyze_btn.configure(state="normal")

    def _clear(self):
        self.url_entry.delete(0, "end")
        self._clear_result_display()

    def _paste(self):
        try:
            import tkinter as tk
            text = self.window.clipboard_get()
            self.url_entry.delete(0, "end")
            self.url_entry.insert(0, text)
        except:
            pass

    def _show_error(self, error_msg):
        self._clear_result_display()
        self.status_label.configure(text="Error", text_color="red")
        self.result_text.configure(state="normal")
        self.result_text.insert("end", f"Terjadi kesalahan:\n{error_msg}")
        self.result_text.configure(state="disabled")

    def run(self):
        self.window.mainloop()


def main():
    app = PhishingDetectorGUI()
    app.run()


if __name__ == "__main__":
    main()
