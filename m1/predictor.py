import os
import sys
import joblib

def resource_path(relative_path):
    """Get absolute path to resource for dev and PyInstaller EXE"""
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

def load_predictor():
    model_path = resource_path("m1/m1_model.pkl")
    vectorizer_path = resource_path("m1/m1_vectorizer.pkl")

    if not os.path.exists(model_path) or not os.path.exists(vectorizer_path):
        raise FileNotFoundError("Model files not found. Train using trainer.py first.")

    clf = joblib.load(model_path)
    vectorizer = joblib.load(vectorizer_path)

    def predict(strings):
        vec = vectorizer.transform(strings)
        return clf.predict(vec)

    return predict
