import joblib
import os
import sys

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and PyInstaller exe """
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

# Use resource_path to locate model files inside the frozen EXE
model_path = resource_path(os.path.join("m1", "m1_family_model.pkl"))
vectorizer_path = resource_path(os.path.join("m1", "m1_family_vectorizer.pkl"))

# Load model and vectorizer
family_clf = joblib.load(model_path)
family_vectorizer = joblib.load(vectorizer_path)

def predict_family(strings):
    combined_text = " ".join(strings)
    features = family_vectorizer.transform([combined_text])
    prediction = family_clf.predict(features)
    return prediction[0]
