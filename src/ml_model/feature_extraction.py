"""
feature_extraction.py
Converts raw network traffic data (captured or dataset) into
numerical features usable by the ML model.
"""

import pandas as pd

# Mapping of protocol numbers to readable names (IANA assigned)
PROTOCOL_MAP = {6: "TCP", 17: "UDP", 1: "ICMP"}

FEATURE_COLUMNS = [
    "packet_size",
    "ttl",
    "src_port",
    "dst_port",
    "protocol_tcp",
    "protocol_udp",
    "protocol_icmp",
]


def load_raw_csv(filepath: str) -> pd.DataFrame:
    """Load a raw captured CSV file into a DataFrame."""
    return pd.read_csv(filepath)


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Transform raw packet data into model-ready numeric features.

    Args:
        df: DataFrame with columns including packet_size, ttl,
            src_port, dst_port, protocol.

    Returns:
        DataFrame with numeric feature columns matching FEATURE_COLUMNS.
    """
    data = df.copy()

    # Fill missing ports (e.g. ICMP has no ports) with 0
    data["src_port"] = pd.to_numeric(data.get("src_port"), errors="coerce").fillna(0)
    data["dst_port"] = pd.to_numeric(data.get("dst_port"), errors="coerce").fillna(0)
    data["packet_size"] = pd.to_numeric(data.get("packet_size"), errors="coerce").fillna(0)
    data["ttl"] = pd.to_numeric(data.get("ttl"), errors="coerce").fillna(0)

    # One-hot encode protocol
    protocol = data.get("protocol", "").astype(str).str.upper()
    data["protocol_tcp"] = (protocol == "TCP").astype(int)
    data["protocol_udp"] = (protocol == "UDP").astype(int)
    data["protocol_icmp"] = (protocol == "ICMP").astype(int)

    return data[FEATURE_COLUMNS]


def prepare_training_data(filepath: str, label_column: str = "label"):
    """
    Load a labeled dataset and split into features (X) and labels (y).

    Args:
        filepath: Path to CSV dataset with a label column
                  (0 = normal, 1 = malicious).
        label_column: Name of the column containing the label.

    Returns:
        (X, y) tuple of DataFrame/Series.
    """
    df = load_raw_csv(filepath)
    y = df[label_column]
    X = extract_features(df)
    return X, y


if __name__ == "__main__":
    # Quick smoke test using dummy data
    sample = pd.DataFrame({
        "packet_size": [64, 1500, 40],
        "ttl": [64, 128, 255],
        "src_port": [443, 22, 0],
        "dst_port": [50213, 50214, 0],
        "protocol": ["TCP", "TCP", "ICMP"],
    })
    print(extract_features(sample))
