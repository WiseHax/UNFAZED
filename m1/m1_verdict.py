import joblib
import os
import sys
from config import M1_VERDICT_MODEL_PATH, M1_VERDICT_VECTORIZER_PATH

model_path = M1_VERDICT_MODEL_PATH
vectorizer_path = M1_VERDICT_VECTORIZER_PATH

try:
    clf = joblib.load(model_path)
    vectorizer = joblib.load(vectorizer_path)
except FileNotFoundError:
    raise FileNotFoundError("Verdict model files not found. Train using trainer.py first.")

def predict_verdict(string):
    vec = vectorizer.transform([string])
    return clf.predict(vec)[0]
