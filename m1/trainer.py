import os
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier

def train_model():
    dataset_path = "training_data.csv"
    if not os.path.exists(dataset_path):
        raise FileNotFoundError(f"{dataset_path} not found. Please create it with 'string,label' format.")

    df = pd.read_csv(dataset_path)
    if 'string' not in df.columns or 'label' not in df.columns:
        raise ValueError("CSV must contain 'string' and 'label' columns")

    X = df['string']
    y = df['label']

    vectorizer = TfidfVectorizer(ngram_range=(1, 2), max_features=3000)
    X_vec = vectorizer.fit_transform(X)

    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_vec, y)

    joblib.dump(clf, "m1_model.pkl")
    joblib.dump(vectorizer, "m1_vectorizer.pkl")
    print("[✓] Model training complete. Saved to m1/")

if __name__ == "__main__":
    train_model()
