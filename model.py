"""
model.py

MACHINE LEARNING INFERENCE MODULE

Responsibilities:
- Load trained ML artifacts (.pkl)
- Vectorize inputs
- Return ML probability scores
- Expose model version

DOES NOT:
- Parse URLs
- Apply heuristics
- Make phishing decisions
- Contain API or DB logic
"""

from typing import Optional, Tuple
import joblib
import string

from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer


# ======================================================
# MODEL METADATA
# ======================================================

MODEL_VERSION = "ml-v1.0.0"


# ======================================================
# SAFE LOAD ML ARTIFACTS
# ======================================================

try:
    MODEL = joblib.load("phishing_combined_model.pkl")
    EMAIL_VECTORIZER: TfidfVectorizer = joblib.load("email_vectorizer.pkl")
    URL_VECTORIZER: TfidfVectorizer = joblib.load("url_vectorizer.pkl")
    ML_AVAILABLE = True
except Exception:
    MODEL = None
    EMAIL_VECTORIZER = None
    URL_VECTORIZER = None
    ML_AVAILABLE = False


# ======================================================
# TEXT NORMALIZATION (ML INPUT ONLY)
# ======================================================

def _clean_text(text: Optional[str]) -> str:
    """
    Minimal text cleaning for ML input.
    Safe and non-destructive.
    """
    if not text:
        return ""
    text = text.lower()
    text = text.translate(str.maketrans("", "", string.punctuation))
    return text


# ======================================================
# ML INFERENCE
# ======================================================

def predict_proba(email_text: Optional[str], url: Optional[str]) -> float:
    """
    Return phishing probability from ML model.

    Returns:
        float in range [0.0, 1.0]

    Fail-safe:
        - Returns 0.0 if model unavailable or error occurs
    """

    if not ML_AVAILABLE:
        return 0.0

    try:
        clean_email = _clean_text(email_text)
        clean_url = _clean_text(url)

        email_vec = EMAIL_VECTORIZER.transform([clean_email])
        url_vec = URL_VECTORIZER.transform([clean_url])

        combined_vec = hstack([email_vec, url_vec])

        # Assumes binary classifier: [legit, phishing]
        proba = MODEL.predict_proba(combined_vec)[0][1]

        return float(proba)

    except Exception:
        # HARD FAIL-SAFE
        return 0.0

