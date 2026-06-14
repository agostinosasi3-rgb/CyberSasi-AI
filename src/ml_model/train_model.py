"""
train_model.py
Trains a machine learning model (Random Forest) to classify
network traffic as 'normal' or 'malicious', and saves it to disk.

Usage:
    python train_model.py --data data/processed/training_data.csv
"""

import argparse
import os
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

from feature_extraction import extract_features

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MODEL_OUTPUT_PATH = os.path.join(_PROJECT_ROOT, "data", "models", "intrusion_model.pkl")


def load_dataset(filepath: str, label_column: str = "label"):
    df = pd.read_csv(filepath)
    if label_column not in df.columns:
        raise ValueError(
            f"Dataset must contain a '{label_column}' column "
            f"(0 = normal, 1 = malicious)."
        )
    y = df[label_column]
    X = extract_features(df)
    return X, y


def train(X, y, test_size=0.2, random_state=42):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=None,
        random_state=random_state,
        class_weight="balanced",
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}\n")
    print("Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["normal", "malicious"]))

    return model


def save_model(model, path=MODEL_OUTPUT_PATH):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    joblib.dump(model, path)
    print(f"\n[INFO] Model saved to: {path}")


def main():
    parser = argparse.ArgumentParser(description="Train CyberSasi AI intrusion detection model")
    parser.add_argument(
        "--data", required=True,
        help="Path to labeled training CSV (must include a 'label' column: 0=normal, 1=malicious)"
    )
    parser.add_argument(
        "--output", default=MODEL_OUTPUT_PATH,
        help="Path to save the trained model (.pkl)"
    )
    args = parser.parse_args()

    print(f"[INFO] Loading dataset from {args.data} ...")
    X, y = load_dataset(args.data)

    print(f"[INFO] Training on {len(X)} samples with {X.shape[1]} features ...")
    model = train(X, y)

    save_model(model, args.output)


if __name__ == "__main__":
    main()
