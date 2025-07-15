import pandas as pd
from supabase_client import supabase

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
    print("✅ Saved as processed_features2.csv")

# Run everything
if __name__ == "__main__":
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
