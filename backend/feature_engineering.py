import pandas as pd
from supabase_client import supabase
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
import joblib

# Fetch data from Supabase
def fetch_raw_data():
    response = supabase.table("network_data").select("*").limit(1000).execute()
    data = pd.DataFrame(response.data)
    return data

# Clean and preprocess the data
def clean_data(df):
    cols_to_convert = [
        "flow_duration", "total_fwd_packets", "total_backward_packets",
        "flow_bytes_sec", "flow_packets_sec", "packet_length_mean",
        "packet_length_std", "fwd_packet_length_mean", "bwd_packet_length_mean",
        "min_packet_length", "max_packet_length", "init_win_bytes_forward",
        "init_win_bytes_backward"
    ]

    # Convert columns to numeric, setting non-convertibles to NaN
    for col in cols_to_convert:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # Fill only the two problematic columns with 0s
    df["init_win_bytes_forward"] = df["init_win_bytes_forward"].fillna(0)
    df["init_win_bytes_backward"] = df["init_win_bytes_backward"].fillna(0)

    # Optionally: drop rows where other columns are still NaN (if any)
    df = df.dropna(subset=cols_to_convert[:-2])  # don't drop based on the 2 filled columns

    return df

# Select final features
def select_features(df):
    return df[[ 
        "flow_duration", "total_fwd_packets", "total_backward_packets",
        "flow_bytes_sec", "flow_packets_sec", "packet_length_mean",
        "packet_length_std", "fwd_packet_length_mean", "bwd_packet_length_mean",
        "min_packet_length", "max_packet_length", "init_win_bytes_forward",
        "init_win_bytes_backward","label"
    ]]

# Save to CSV
def save_features_to_csv(df):
    df.to_csv("processed_features2.csv", index=False)
    print("Saved as processed_features2.csv")

# Load processed features dataset
DATA_PATH = 'backend/processed_features2.csv'
df = pd.read_csv(DATA_PATH)

# Select feature columns (exclude label if present)
feature_cols = [col for col in df.columns if col != 'label']
X = df[feature_cols].values

# Standardize features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train IsolationForest
iso_forest = IsolationForest(contamination='auto', random_state=42)
iso_forest.fit(X_scaled)

# Train OneClassSVM
ocsvm = OneClassSVM(nu=0.05, kernel='rbf', gamma='auto')
ocsvm.fit(X_scaled)

# Save models and scaler
joblib.dump(iso_forest, 'isolation_forest_model.joblib')
joblib.dump(ocsvm, 'oneclass_svm_model.joblib')
joblib.dump(scaler, 'scaler.joblib')

print('IsolationForest, OneClassSVM, and scaler saved.')

# Run everything
if __name__ == "__main__":
    # Test: Load models and run a sample prediction
    iso_forest_loaded = joblib.load('isolation_forest_model.joblib')
    ocsvm_loaded = joblib.load('oneclass_svm_model.joblib')
    scaler_loaded = joblib.load('scaler.joblib')

    # Take a sample (first row) from the dataset
    sample = X[0].reshape(1, -1)
    sample_scaled = scaler_loaded.transform(sample)

    iso_pred = iso_forest_loaded.predict(sample_scaled)
    ocsvm_pred = ocsvm_loaded.predict(sample_scaled)

    print(f"Sample IsolationForest prediction: {iso_pred[0]}")
    print(f"Sample OneClassSVM prediction: {ocsvm_pred[0]}")

    raw_data = fetch_raw_data()
    print("Raw data rows fetched:", len(raw_data))
    print("Raw data preview:")
    print(raw_data.head())

    clean_df = clean_data(raw_data)
    features = select_features(clean_df)

    print("Final features shape:", features.shape)
    print("Feature sample:")
    print(features.head())

    save_features_to_csv(features)
