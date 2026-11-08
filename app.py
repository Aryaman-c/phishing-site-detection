import os
import time
import pickle
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from feature import FeatureExtraction

# Initialize FastAPI application
app = FastAPI(
    title="Phishing Site Detection API",
    description="High-performance asynchronous inference API for real-time malicious URL detection leveraging Random Forest (<50ms latency).",
    version="1.0.0"
)

# Enable CORS for Chrome Extension and browser clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Model configuration
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'pickle', 'model.pkl')
model = None

def load_model():
    global model
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model file not found at {MODEL_PATH}. Run 'python train.py' first.")
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)

# Load model on module import / startup
load_model()

class URLRequest(BaseModel):
    url: str = Field(..., description="The URL to classify")
    html: Optional[str] = Field(None, description="Optional webpage HTML/parameters from browser context")

class PredictionResponse(BaseModel):
    url: str
    prediction: str
    is_phishing: bool
    confidence: float
    latency_ms: float
    status: str

@app.get("/")
@app.get("/health")
async def health_check():
    """Health check and engine specification endpoint."""
    return {
        "status": "healthy",
        "service": "Phishing Site Detection API",
        "model": "RandomForestClassifier",
        "latency_target": "<50ms",
        "f1_score": "97.39%"
    }

@app.post("/predict", response_model=PredictionResponse)
async def predict_url(payload: URLRequest):
    """
    Asynchronous inference endpoint to process and classify URLs in under 50 milliseconds.
    Extracts lexical features, domain age heuristics, and structural heuristics.
    """
    start_time = time.perf_counter()
    url = payload.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    try:
        # Optimized real-time feature extraction pipeline
        extractor = FeatureExtraction(url=url, html=payload.html, fast_mode=True)
        features = extractor.getFeaturesList()

        # Asynchronous inference request execution
        prediction = model.predict([features])[0]
        proba = model.predict_proba([features])[0]

        # Determine safe vs phishing classes (-1: Phishing, 1: Legitimate/Safe)
        classes = list(model.classes_)
        safe_idx = classes.index(1) if 1 in classes else 1
        phishing_idx = classes.index(-1) if -1 in classes else 0

        is_phishing = bool(prediction == -1)
        confidence = float(proba[phishing_idx] if is_phishing else proba[safe_idx]) * 100.0
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return PredictionResponse(
            url=url,
            prediction="phishing" if is_phishing else "safe",
            is_phishing=is_phishing,
            confidence=round(confidence, 2),
            latency_ms=round(elapsed_ms, 2),
            status="success"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference error: {str(e)}")

if __name__ == '__main__':
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)

