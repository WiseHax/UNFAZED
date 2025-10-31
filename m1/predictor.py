import os
import sys
import joblib
from config import M1_PREDICTOR_MODEL_PATH, M1_PREDICTOR_VECTORIZER_PATH

model_path = M1_PREDICTOR_MODEL_PATH
vectorizer_path = M1_PREDICTOR_VECTORIZER_PATH

def load_predictor():
    if not os.path.exists(model_path) or not os.path.exists(vectorizer_path):
        raise FileNotFoundError("Model files not found. Train using trainer.py first.")

    clf = joblib.load(model_path)
    vectorizer = joblib.load(vectorizer_path)

    def predict(strings):
        vec = vectorizer.transform(strings)
        return clf.predict(vec)

    return predict
