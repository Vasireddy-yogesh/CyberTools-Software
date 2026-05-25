"""
phishing_logic.py

LOW-LEVEL PHISHING DETECTION UTILITIES

Contains:
- ML model loading
- Text cleaning
- Feature vectorization
- Heuristic helper functions
- ML-based phishing prediction

DOES NOT CONTAIN:
- API logic
- Risk scoring
- Decision thresholds
- FastAPI imports
"""

import string
import joblib
from typing import Optional

from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer


# ======================================================
# LOAD ML ARTIFACTS (SAFE)
# ======================================================

try:
    MODEL = joblib.load("phishing_combined_model.pkl")
    EMAIL_VECTORIZER: TfidfVectorizer = joblib.load("email_vectorizer.pkl")
    URL_VECTORIZER: TfidfVectorizer = joblib.load("url_vectorizer.pkl")
    ML_AVAILABLE = True
except Exception:
    # Fail-safe: system must NEVER crash
    MODEL = None
    EMAIL_VECTORIZER = None
    URL_VECTORIZER = None
    ML_AVAILABLE = False


# ======================================================
# STATIC DATA (KEYWORDS / TLDs)
# ======================================================

PHISHING_KEYWORDS = {
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "bank", "payment", "invoice", "billing", "alert",
    "suspend", "locked", "unlock", "confirm", "refund", "support"
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "club", "info", "click",
    "support", "loan", "gq", "cf"
}


# ======================================================
# TEXT CLEANING
# ======================================================

def clean_text(text: Optional[str]) -> str:
    """
    Normalize input text safely.
    Never throws.
    """
    if not text:
        return ""
    text = text.lower()
    text = text.translate(str.maketrans("", "", string.punctuation))
    return text


# ======================================================
# HEURISTIC HELPERS (PURE FUNCTIONS)
# ======================================================

def has_suspicious_keyword(text: str) -> bool:
    t = text.lower()
    return any(keyword in t for keyword in PHISHING_KEYWORDS)


def has_multiple_hyphens(domain: str) -> bool:
    return domain.count("-") >= 2


def has_digit_masquerading(domain: str) -> bool:
    """
    Detect common leetspeak tricks:
    0 -> o, 1 -> l/i, 3 -> e, 5 -> s
    """
    return any(ch in domain for ch in {"0", "1", "3", "5"})


def has_suspicious_tld(domain: str) -> bool:
    if "." not in domain:
        return False
    tld = domain.rsplit(".", 1)[-1]
    return tld in SUSPICIOUS_TLDS


# ======================================================
# ML-BASED PHISHING DETECTION
# ======================================================

def detect_phishing_ml(email_text: str, url: str) -> str:
    """
    ML-only phishing detection.

    Returns:
        "Phishing"
        "Legitimate"

    FAIL-SAFE:
    - If ML artifacts are missing or error occurs,
      returns "Legitimate" (fail-open).
    """
    if not ML_AVAILABLE:
        return "Legitimate"

    try:
        clean_email = clean_text(email_text)
        clean_url = clean_text(url)

        vec_email = EMAIL_VECTORIZER.transform([clean_email])
        vec_url = URL_VECTORIZER.transform([clean_url])

        combined_vector = hstack([vec_email, vec_url])
        prediction = MODEL.predict(combined_vector)[0]

        return "Phishing" if int(prediction) == 1 else "Legitimate"

    except Exception:
        # NEVER crash the system
        return "Legitimate"
