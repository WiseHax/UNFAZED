import joblib
import os
import sys
from config import M1_FAMILY_MODEL_PATH, M1_FAMILY_VECTORIZER_PATH

model_path = M1_FAMILY_MODEL_PATH
vectorizer_path = M1_FAMILY_VECTORIZER_PATH

# Load model and vectorizer
try:
    family_clf = joblib.load(model_path)
    family_vectorizer = joblib.load(vectorizer_path)
except FileNotFoundError:
    raise FileNotFoundError("Malware family model files not found. Train using trainer.py first.")

def predict_family(strings):
    if not strings:
        return "unknown"
    combined_text = " ".join(strings)
    features = family_vectorizer.transform([combined_text])
    prediction = family_clf.predict(features)
    return prediction[0]
