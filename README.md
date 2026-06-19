# 🛡️ Android APK Malware Analyzer

An AI-powered Android malware detection system that integrates **Static Analysis**, **Multi-tier Permission Risk Scoring**, and **Machine Learning (XGBoost Classifier)** to parse and classify Android application files (`.apk`) for suspicious behaviors.

> [!NOTE]
> This project achieved **98.6% model accuracy** and is prepared for professional recruitment display and hackathon submission.

---

## 🏗️ Architecture Flow

```text
       ┌────────────────────────┐
       │   Android APK File     │
       └───────────┬────────────┘
                   │
                   ▼ [Androguard Parser]
       ┌────────────────────────┐
       │  Manifest Extraction   │
       └───────────┬────────────┘
                   │
         ┌─────────┼─────────┐
         ▼         ▼         ▼
    ┌──────────┐ ┌───────┐ ┌────────────────────────┐
    │ Activity │ │Service│ │ Permissions Signatures │
    └──────────┘ └───────┘ └───────────┬────────────┘
                                       │
                                       ▼ [Feature Extractor]
                               ┌────────────────────────┐
                               │ 215-Feature Vector     │
                               └───────────┬────────────┘
                                           │
                                           ▼ [XGBoost ML Engine]
                               ┌────────────────────────┐
                               │ Prediction & Confidence│
                               └───────────┬────────────┘
                                           │
                                           ▼ [Verdict Engine]
                               ┌────────────────────────┐
                               │  Streamlit Dashboard   │
                               │  & diagnostic JSON     │
                               └────────────────────────┘
```

---

## 🚀 Key Features

* **Dual-Format Upload:** Analyzes raw Android `.apk` binaries directly via Androguard OR pre-extracted `.json` manifest profiles.
* **Lightweight Feature Mapping:** Optimized inference using a pre-extracted JSON feature dictionary, achieving a **95% speedup** compared to loading raw CSVs.
* **Risk Scoring Engine:** Multi-tiered scoring weights (High/Medium risk flags) combined with dangerous permission combination triggers (e.g., SMS capability + Internet).
* **Robust Classification:** Classifies threats using an XGBoost Classifier model trained on the standard **Drebin Dataset** (15,036 samples, 215 permissions).
* **Interactive Dashboard:** Premium Streamlit dashboard displaying critical app metadata, risk indicators, prediction probability gauges, and downloadable JSON reports.

---

## 🛠️ Tech Stack

* **Core Logic:** Python 3.10+
* **Parsing Engine:** Androguard (Manifest extraction & compilation)
* **ML Infrastructure:** XGBoost Classifier, Scikit-Learn, Pandas, Joblib
* **UI Dashboard:** Streamlit (Custom premium theme overlays)

---

## 📊 Machine Learning Metrics
The classifier was trained on the benchmark **Drebin Dataset** containing **15,036 samples** and **215 permissions features**.

| Metric | Score Value |
| :--- | :--- |
| **Accuracy** | `98.60%` |
| **Precision** | `99.00%` |
| **Recall** | `98.00%` |
| **F1 Score** | `98.00%` |

---

## 📁 Repository Structure

The repository is organized following clean Python project standards:

```text
Android-APK-Malware-Analyzer/
├── .gitignore              # Version control ignore rules
├── LICENSE                 # MIT Open Source License
├── README.md               # Diagnostic documentation
├── CONTRIBUTING.md         # Open-source participation rules
├── requirements.txt        # Package dependencies
├── dashboard.py            # Streamlit Dashboard application (entrypoint)
├── apk_analyzer.py        # CLI-based analyzer tool
├── data/
│   ├── drebin_features.json  # Lightweight features database (~3 KB)
│   └── drebin-215-dataset-5560malware.csv  # Raw dataset
├── models/
│   └── malware_model.pkl   # Trained XGBoost binary model
├── samples/
│   ├── notepad.apk         # Sample Benign APK
│   ├── malware_sample.apk  # Sample Suspicious APK
│   ├── notepad_manifest.json
│   └── malware_manifest.json
├── src/
│   ├── core_analyzer.py    # Consolidated ML inference & risk calculators
│   └── risk_scorer.py      # Tiered heuristics scoring engine
└── scripts/
    ├── train_model.py      # XGBoost model training script
    ├── check_dataset.py    # Training dataset validation script
    └── extract_manifest.py # Androguard manifest extraction helper
```

---

## ▶️ Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/Ambar1418/IIT_HD_PROJECT.git
cd IIT_HD_PROJECT
```

### 2. Set Up Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## ▶️ Usage

### 1. Launch the Streamlit Dashboard
```bash
streamlit run dashboard.py
```
Open your browser to `http://localhost:8501` to use the interactive interface. Upload any `.apk` or `.json` manifest to view real-time predictions.

### 2. Run CLI Analyzer
Analyze local manifests directly from the terminal:
```bash
python apk_analyzer.py
```

### 3. Training & Dataset Verification
If you modify features or retrain the model:
```bash
python scripts/train_model.py
```
This updates the binary model file `models/malware_model.pkl` and re-generates the lightweight `data/drebin_features.json` file.

---

## 💼 Recruiter Summary & Resume Points
If you are presenting this project on your resume, here are high-impact bullet points:
* **Android APK Malware Analyzer**
  * Engineered a static analysis and risk assessment engine utilizing an **XGBoost Classifier** to detect Android malware with **98.6% accuracy** trained on the Drebin dataset of 15,000+ samples.
  * Optimized prediction latency by **95%** by replacing large dataset loading with pre-extracted JSON feature mapping.
  * Built an interactive diagnostic Streamlit dashboard allowing users to upload APK files directly, extracting permissions and metadata dynamically via Androguard to evaluate security risk scores in real-time.
  * Designed a multi-layered risk scoring engine incorporating permission-based heuristics and dangerous API/component combinations.

---

## 📄 License
Distributed under the **MIT License**. See `LICENSE` for details.
