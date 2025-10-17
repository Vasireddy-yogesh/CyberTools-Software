# backend/main.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib

# ==================== LOAD MODEL ====================
try:
    model = joblib.load("phishing_model.pkl")     # your trained model
    vectorizer = joblib.load("vectorizer.pkl")    # your text/vectorizer
except Exception as e:
    raise RuntimeError(f"Failed to load model/vectorizer: {e}")

# ==================== FASTAPI APP ====================
app = FastAPI(title="CyberSecure Phishing API")

# ==================== SCHEMA ====================
class URLData(BaseModel):
    url: str

# ==================== HELPER ====================
def preprocess_url(url: str) -> str:
    return url.lower().strip()

# ==================== ENDPOINTS ====================
@app.post("/predict")
def predict(data: URLData):
    """
    Predict if a URL is phishing or legitimate.
    Returns: {"url": ..., "prediction": "phishing"/"legitimate", "confidence": float or None}
    """
    try:
        cleaned_url = preprocess_url(data.url)
        vectorized_url = vectorizer.transform([cleaned_url])
        prediction = model.predict(vectorized_url)[0]

        result = "phishing" if prediction == 1 else "legitimate"

        # Optional: calculate probability if model supports it
        probability = None
        if hasattr(model, "predict_proba"):
            prob_array = model.predict_proba(vectorized_url)[0]
            # If classification is 0/1, probability of phishing is at index 1
            probability = float(prob_array[1]) if len(prob_array) > 1 else float(prob_array[0])

        return {
            "url": data.url,
            "prediction": result,
            "confidence": probability
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {e}")


@app.get("/")
def root():
    return {"message": "CyberSecure Phishing API running"}
