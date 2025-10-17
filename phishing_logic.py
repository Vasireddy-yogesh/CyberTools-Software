import joblib
import string
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer

# Load model and vectorizers
model = joblib.load("phishing_combined_model.pkl")
email_vectorizer = joblib.load("email_vectorizer.pkl")
url_vectorizer = joblib.load("url_vectorizer.pkl")

# Clean text
def clean_text(text):
    if not text:
        return ""
    text = text.lower()
    text = text.translate(str.maketrans('', '', string.punctuation))
    return text

# Prediction function
def detect_phishing(email_text: str, url: str) -> str:
    clean_e = clean_text(email_text)
    clean_u = clean_text(url)
    
    vec_email = email_vectorizer.transform([clean_e])
    vec_url = url_vectorizer.transform([clean_u])
    
    combined_vec = hstack([vec_email, vec_url])
    prediction = model.predict(combined_vec)[0]

    return "Phishing" if prediction == 1 else "Legitimate"
