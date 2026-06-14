"""
predict.py
Loads the trained intrusion detection model and classifies
new network traffic records as 'normal' or 'malicious'.
"""

import os
import joblib
import pandas as pd

from feature_extraction import extract_features

# Resolve project root: src/ml_model/predict.py -> project_root
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MODEL_PATH = os.path.join(_PROJECT_ROOT, "data", "models", "intrusion_model.pkl")

_model = None


def load_model(path: str = MODEL_PATH):
    """Load the trained model from disk (cached after first load)."""
    global _model
    if _model is None:
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"Model file not found at '{path}'. "
                f"Run train_model.py first to create it."
            )
        _model = joblib.load(path)
        print(f"[INFO] Loaded model from {path}")
    return _model


def predict(records: pd.DataFrame, model_path: str = MODEL_PATH) -> pd.DataFrame:
    """
    Classify traffic records as normal (0) or malicious (1).

    Args:
        records: DataFrame of raw packet records (same columns as captured data).
        model_path: Path to the trained model file.

    Returns:
        DataFrame with an added 'prediction' and 'label' column.
    """
    model = load_model(model_path)
    X = extract_features(records)

    predictions = model.predict(X)
    probabilities = model.predict_proba(X)[:, 1]  # probability of 'malicious'

    result = records.copy()
    result["prediction"] = predictions
    result["label"] = result["prediction"].map({0: "normal", 1: "malicious"})
    result["confidence"] = probabilities.round(4)

    return result


if __name__ == "__main__":
    # Example usage with a sample record
    sample = pd.DataFrame({
        "src_ip": ["192.168.1.10"],
        "dst_ip": ["192.168.1.1"],
        "protocol": ["TCP"],
        "src_port": [443],
        "dst_port": [54213],
        "packet_size": [1500],
        "ttl": [64],
    })

    try:
        result = predict(sample)
        print(result[["src_ip", "dst_ip", "label", "confidence"]])
    except FileNotFoundError as e:
        print(f"[WARNING] {e}")
