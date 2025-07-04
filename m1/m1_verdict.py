import joblib
import os

# Load trained model and vectorizer using absolute paths
model_path = os.path.join(os.path.dirname(__file__), "m1_model.pkl")
vectorizer_path = os.path.join(os.path.dirname(__file__), "m1_vectorizer.pkl")

clf = joblib.load(model_path)
vectorizer = joblib.load(vectorizer_path)

def predict_verdict(string):
    vec = vectorizer.transform([string])
    return clf.predict(vec)[0]
