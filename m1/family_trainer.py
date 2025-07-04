import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import joblib
import os

def train_family_model():
    df = pd.read_csv("family_data.csv")
    X = df["string"]
    y = df["label"]

    vectorizer = TfidfVectorizer()
    X_vec = vectorizer.fit_transform(X)

    clf = LogisticRegression(max_iter=1000)
    clf.fit(X_vec, y)

    os.makedirs("m1", exist_ok=True)
    joblib.dump(clf, "m1_family_model.pkl")
    joblib.dump(vectorizer, "m1_family_vectorizer.pkl")
    print("✓ Malware family model and vectorizer saved.")

if __name__ == "__main__":
    train_family_model()
