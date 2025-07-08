import joblib
import os
import sys

print("[DEBUG] m1_verdict loaded from:", __file__)

def get_resource_path(filename):
    if getattr(sys, 'frozen', False):
        # Inside PyInstaller .exe
        base_path = sys._MEIPASS
        return os.path.join(base_path, "m1", filename)
    else:
        # Running normally (e.g., in VSCode or during development)
        return os.path.join(os.path.dirname(__file__), "m1", filename)

model_path = get_resource_path("m1_model.pkl")
vectorizer_path = get_resource_path("m1_vectorizer.pkl")

clf = joblib.load(model_path)
vectorizer = joblib.load(vectorizer_path)

def predict_verdict(string):
    vec = vectorizer.transform([string])
    return clf.predict(vec)[0]
