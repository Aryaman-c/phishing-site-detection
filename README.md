# Phishing Site Detection

An end-to-end, real-time malicious URL detection system powered by Machine Learning, a high-performance asynchronous FastAPI backend, and a lightweight Chrome Browser Extension.

## 🚀 Key Highlights

- **Real-Time Malicious URL Detection Engine**: Leverages a tuned **Random Forest classifier** evaluating 30 comprehensive features spanning lexical URL properties, domain age & DNS heuristics, and structural page heuristics.
- **Lightweight Chrome Browser Extension**: Pure JavaScript Manifest V3 extension that intercepts navigation requests (`webNavigation`) and analyzes webpage parameters (form actions, password fields, suspicious redirections) to block phishing attempts instantly.
- **High-Performance FastAPI Backend**: Handles asynchronous inference requests with an optimized feature extraction pipeline designed to process and classify URLs in **under 50 milliseconds**.
- **50,000+ URL Dataset & 97% F1-Score**: Aggregated and preprocessed a balanced dataset of 50,000+ legitimate and phishing URLs, applying advanced feature engineering and class weighting to achieve a **97% F1-score** while minimizing false positives.

---

## 📁 Project Structure

```
├── app.py                  # Minimal, high-performance FastAPI asynchronous backend
├── data_preprocessing.py   # Aggregates and preprocesses 50,000+ URLs dataset
├── feature.py              # Optimized feature extraction pipeline (< 50ms)
├── predict_url.py          # Command-line URL classification utility
├── train.py                # Model training script for Random Forest classifier
├── requirements.txt        # Python dependencies
├── phishing.csv            # Original base dataset
├── phishing_50k.csv        # Preprocessed 50,000+ sample dataset
├── pickle/
│   └── model.pkl           # Trained Random Forest classifier
└── extension/              # Lightweight Chrome Browser Extension (Manifest V3)
    ├── manifest.json       # Extension configuration and permissions
    ├── background.js       # Navigation interceptor & async API communicator
    ├── content.js          # Webpage parameter and form heuristic analyzer
    ├── blocked.html        # Safety warning screen for blocked phishing attempts
    ├── blocked.js          # Blocking page logic
    ├── popup.html          # Extension popup UI
    ├── popup.css           # Styling
    ├── popup.js            # Popup status & interactive URL scanner
    └── icons/              # Extension icons (16px, 48px, 128px)
```

---

## 🛠️ Installation & Setup

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Dataset Preprocessing & Model Training
To regenerate the 50,000+ sample preprocessed dataset and train the Random Forest model (achieving 97% F1-score):
```bash
# Aggregates and preprocesses 50,000+ samples
python data_preprocessing.py

# Trains and saves Random Forest model to pickle/model.pkl
python train.py
```

### 3. Start the FastAPI Inference Backend
Run the high-performance asynchronous API server:
```bash
python app.py
```
Or via Uvicorn directly:
```bash
uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```
The API provides:
- `POST /predict`: Asynchronous classification endpoint (`url`, optional `html`). Returns verdict, confidence, and latency in milliseconds (`< 50ms`).
- `GET /health`: Health and engine metadata endpoint.
- Interactive API documentation available at: `http://127.0.0.1:8000/docs`

### 4. Load the Chrome Browser Extension
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (toggle switch in the top-right corner).
3. Click **Load unpacked**.
4. Select the `extension/` folder inside this project directory.
5. The extension will now actively intercept navigation requests, analyze webpage parameters, and block malicious phishing sites in real time!

### 5. CLI URL Prediction
You can also classify individual URLs directly from the terminal:
```bash
python predict_url.py "https://www.google.com"
# Output: URL is SAFE: https://www.google.com (100.0% confidence)

python predict_url.py "http://paypal-verification.account-security-alert.xyz/update-login.php?user=1"
# Output: URL is PHISHING: http://paypal-verification.account-security-alert.xyz/update-login.php?user=1 (100.0% confidence)
```

---

## 📊 Model Performance Metrics

| Metric | Score |
| :--- | :--- |
| **Model** | Random Forest Classifier |
| **Dataset Size** | 52,000 URLs |
| **Weighted F1-Score** | **97.39%** (~97%) |
| **Legitimate Precision** | **97.97%** (Minimizing False Positives) |
| **Phishing Recall** | **97.46%** |
| **Inference Latency** | **< 20 ms** (Target: < 50ms) |

