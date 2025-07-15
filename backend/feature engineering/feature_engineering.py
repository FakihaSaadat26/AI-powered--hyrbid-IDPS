import pandas   as pd
from supabase_client import supabase

# fetching data from supabase
def fetch_raw_data():
    response = supabase.table("network_data").select("*").limit(1000).execute()
    data = pd.DataFrame(response.data)
    return data
# cleaning data
def clean_data(df):
    # Drop rows with nulls
    df = df.dropna()

    # Convert necessary columns to numeric
    cols_to_convert = [
        "flow_duration", "total_fwd_packets", "total_backward_packets",
        "flow_bytes_sec", "flow_packets_sec", "packet_length_mean",
        "packet_length_std", "fwd_packet_length_mean", "bwd_packet_length_mean",
        "min_packet_length", "max_packet_length", "init_win_bytes_forward",
        "init_win_bytes_backward"
    ]
    for col in cols_to_convert:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    
    return df
    #selecting features
def select_features(df):
    return df[[
        "flow_duration", "total_fwd_packets", "total_backward_packets",
        "flow_bytes_sec", "flow_packets_sec", "packet_length_mean",
        "packet_length_std", "fwd_packet_length_mean", "bwd_packet_length_mean",
        "min_packet_length", "max_packet_length", "init_win_bytes_forward",
        "init_win_bytes_backward"
    ]]
# saving features to csv
def save_features_to_csv(df):
    df.to_csv("processed_features.csv", index=False)
    print("✅ Saved as processed_features.csv")

if __name__ == "__main__":
    raw_data = fetch_raw_data()
    clean_df = clean_data(raw_data)
    features = select_features(clean_df)
    save_features_to_csv(features)