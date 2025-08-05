import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
import joblib
from supabase_client import supabase
import warnings
warnings.filterwarnings('ignore')

def fetch_raw_data():
    """Fetch data from Supabase with better error handling"""
    try:
        response = supabase.table("network_data").select("*").limit(1000).execute()
        data = pd.DataFrame(response.data)
        print(f"✅ Fetched {len(data)} records from Supabase")
        return data
    except Exception as e:
        print(f"❌ Error fetching data: {e}")
        return pd.DataFrame()

def generate_synthetic_training_data(base_df, num_samples=500):
    """Generate diverse synthetic training data to ensure model variety"""
    print("🔧 Generating synthetic training data for better model performance...")
    
    synthetic_data = []
    
    # Normal traffic patterns (70% of data)
    for _ in range(int(num_samples * 0.7)):
        record = {
            "flow_duration": np.random.uniform(0.01, 2.0),
            "total_fwd_packets": np.random.randint(1, 50),
            "total_backward_packets": np.random.randint(1, 30),
            "flow_bytes_sec": np.random.uniform(1000, 10000),
            "flow_packets_sec": np.random.uniform(10, 100),
            "packet_length_mean": np.random.uniform(500, 1200),
            "packet_length_std": np.random.uniform(50, 300),
            "fwd_packet_length_mean": np.random.uniform(500, 1200),
            "bwd_packet_length_mean": np.random.uniform(400, 1100),
            "min_packet_length": 64,
            "max_packet_length": np.random.randint(1200, 1518),
            "init_win_bytes_forward": 0,
            "init_win_bytes_backward": 0,
            "src_ip": f"192.168.1.{np.random.randint(1, 254)}",
            "dst_ip": f"10.0.0.{np.random.randint(1, 254)}",
            "dst_port": np.random.choice([80, 443, 22, 21, 25])
        }
        synthetic_data.append(record)
    
    # Attack patterns (30% of data) - These should be detected as anomalies
    attack_patterns = [
        # DDoS patterns
        {
            "flow_duration": np.random.uniform(5.0, 30.0),
            "total_fwd_packets": np.random.randint(500, 2000),
            "total_backward_packets": np.random.randint(1, 10),
            "flow_bytes_sec": np.random.uniform(50000, 200000),
            "flow_packets_sec": np.random.uniform(200, 1000),
            "packet_length_mean": 64,
            "packet_length_std": np.random.uniform(1, 20),
            "fwd_packet_length_mean": 64,
            "bwd_packet_length_mean": 64,
            "min_packet_length": 64,
            "max_packet_length": 64,
        },
        # Port scan patterns
        {
            "flow_duration": np.random.uniform(0.001, 0.1),
            "total_fwd_packets": 1,
            "total_backward_packets": 0,
            "flow_bytes_sec": np.random.uniform(100, 1000),
            "flow_packets_sec": np.random.uniform(1, 10),
            "packet_length_mean": 64,
            "packet_length_std": 0,
            "fwd_packet_length_mean": 64,
            "bwd_packet_length_mean": 0,
            "min_packet_length": 64,
            "max_packet_length": 64,
        },
        # Slow attacks
        {
            "flow_duration": np.random.uniform(30.0, 300.0),
            "total_fwd_packets": np.random.randint(1, 5),
            "total_backward_packets": np.random.randint(1, 3),
            "flow_bytes_sec": np.random.uniform(1, 100),
            "flow_packets_sec": np.random.uniform(0.1, 1),
            "packet_length_mean": np.random.uniform(100, 500),
            "packet_length_std": np.random.uniform(10, 100),
            "fwd_packet_length_mean": np.random.uniform(100, 500),
            "bwd_packet_length_mean": np.random.uniform(100, 400),
            "min_packet_length": 64,
            "max_packet_length": np.random.randint(200, 800),
        }
    ]
    
    # Generate attack samples (30% of data)
    for _ in range(int(num_samples * 0.3)):
        base_pattern = np.random.choice(attack_patterns)
        record = {
            **base_pattern,
            "init_win_bytes_forward": 0,
            "init_win_bytes_backward": 0,
            "src_ip": f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 254)}",
            "dst_ip": f"10.0.0.{np.random.randint(1, 254)}",
            "dst_port": np.random.choice([80, 443, 22, 21, 25, 3389, 1433, 3306])
        }
        synthetic_data.append(record)
    
    synthetic_df = pd.DataFrame(synthetic_data)
    
    # Combine with original data if available
    if not base_df.empty:
        combined_df = pd.concat([base_df, synthetic_df], ignore_index=True)
    else:
        combined_df = synthetic_df
    
    print(f"✅ Generated {len(synthetic_df)} synthetic samples")
    print(f"✅ Total training data: {len(combined_df)} samples")
    
    return combined_df

def clean_data(df):
    """Clean and preprocess the data with better handling"""
    print("🔧 Cleaning data...")
    
    cols_to_convert = [
        "flow_duration", "total_fwd_packets", "total_backward_packets",
        "flow_bytes_sec", "flow_packets_sec", "packet_length_mean",
        "packet_length_std", "fwd_packet_length_mean", "bwd_packet_length_mean",
        "min_packet_length", "max_packet_length", "init_win_bytes_forward",
        "init_win_bytes_backward"
    ]
    
    # Add missing columns with default values
    for col in cols_to_convert:
        if col not in df.columns:
            if col in ["init_win_bytes_forward", "init_win_bytes_backward"]:
                df[col] = 0
            elif col == "min_packet_length":
                df[col] = 64
            elif col == "max_packet_length":
                df[col] = 1518
            else:
                df[col] = 0

    # Convert columns to numeric
    for col in cols_to_convert:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # Fill NaN values strategically
    df["init_win_bytes_forward"] = df["init_win_bytes_forward"].fillna(0)
    df["init_win_bytes_backward"] = df["init_win_bytes_backward"].fillna(0)
    
    # For other columns, fill with median values
    for col in cols_to_convert[:-2]:  # Exclude the two we already filled
        if df[col].isna().any():
            median_val = df[col].median()
            df[col] = df[col].fillna(median_val)

    # Remove any remaining rows with NaN
    initial_count = len(df)
    df = df.dropna(subset=cols_to_convert)
    final_count = len(df)
    
    if initial_count != final_count:
        print(f"⚠️  Dropped {initial_count - final_count} rows due to missing values")
    
    print(f"✅ Data cleaned: {len(df)} records ready")
    return df

def select_features(df):
    """Select and validate features"""
    feature_columns = [
        "flow_duration", "total_fwd_packets", "total_backward_packets",
        "flow_bytes_sec", "flow_packets_sec", "packet_length_mean",
        "packet_length_std", "fwd_packet_length_mean", "bwd_packet_length_mean",
        "min_packet_length", "max_packet_length", "init_win_bytes_forward",
        "init_win_bytes_backward"
    ]
    
    features_df = df[feature_columns].copy()
    
    # Check for feature variety
    print("🔍 Checking feature variety...")
    for col in feature_columns:
        unique_vals = features_df[col].nunique()
        print(f"  {col}: {unique_vals} unique values")
        
        if unique_vals < 2:
            print(f"⚠️  Warning: {col} has low variety, adding noise...")
            # Add small amount of noise to constant features
            noise = np.random.normal(0, 0.01, len(features_df))
            features_df[col] = features_df[col] + noise
    
    return features_df

def train_models_with_variety(X_scaled):
    """Train models with parameters optimized for variety"""
    print("🤖 Training ML models...")
    
    # Print data statistics
    print(f"📊 Training data shape: {X_scaled.shape}")
    print(f"📊 Feature means: {np.mean(X_scaled, axis=0)[:5]}...")  # First 5 features
    print(f"📊 Feature stds: {np.std(X_scaled, axis=0)[:5]}...")   # First 5 features
    
    # Train IsolationForest with better parameters
    print("🌲 Training IsolationForest...")
    iso_forest = IsolationForest(
        contamination=0.1,      # Expect 10% outliers
        random_state=42,
        n_estimators=200,       # More trees for better performance
        max_samples='auto',
        bootstrap=False
    )
    iso_forest.fit(X_scaled)
    
    # Train OneClassSVM with better parameters
    print("🔮 Training OneClassSVM...")
    ocsvm = OneClassSVM(
        nu=0.1,                 # Expect 10% outliers (same as contamination)
        kernel='rbf',
        gamma='scale',          # Better than 'auto' for newer sklearn
        shrinking=True,
        cache_size=200
    )
    ocsvm.fit(X_scaled)
    
    # Test model variety on training data
    print("🧪 Testing model variety...")
    iso_preds = iso_forest.predict(X_scaled)
    ocsvm_preds = ocsvm.predict(X_scaled)
    
    iso_normal = np.sum(iso_preds == 1)
    iso_anomaly = np.sum(iso_preds == -1)
    ocsvm_normal = np.sum(ocsvm_preds == 1)
    ocsvm_anomaly = np.sum(ocsvm_preds == -1)
    
    print(f"✅ IsolationForest: {iso_normal} normal, {iso_anomaly} anomalies")
    print(f"✅ OneClassSVM: {ocsvm_normal} normal, {ocsvm_anomaly} anomalies")
    
    if iso_anomaly == 0 or ocsvm_anomaly == 0:
        print("⚠️  Warning: One model detected no anomalies!")
    
    return iso_forest, ocsvm

def save_models_and_scaler(iso_forest, ocsvm, scaler):
    """Save trained models"""
    print("💾 Saving models...")
    
    joblib.dump(iso_forest, 'isolation_forest_model.joblib')
    joblib.dump(ocsvm, 'oneclass_svm_model.joblib')
    joblib.dump(scaler, 'scaler.joblib')
    
    print('✅ IsolationForest, OneClassSVM, and scaler saved successfully')

def test_model_predictions():
    """Test the trained models with known normal/attack samples"""
    print("🧪 Testing model predictions with known samples...")
    
    # Load the saved models
    import os
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    iso_forest = joblib.load(os.path.join(backend_dir, 'isolation_forest_model.joblib'))
    ocsvm = joblib.load(os.path.join(backend_dir, 'oneclass_svm_model.joblib'))
    scaler = joblib.load(os.path.join(backend_dir, 'scaler.joblib'))
    
    # Test samples
    normal_sample = {
        "flow_duration": 0.5,
        "total_fwd_packets": 20,
        "total_backward_packets": 15,
        "flow_bytes_sec": 5000,
        "flow_packets_sec": 70,
        "packet_length_mean": 800,
        "packet_length_std": 200,
        "fwd_packet_length_mean": 850,
        "bwd_packet_length_mean": 750,
        "min_packet_length": 64,
        "max_packet_length": 1500,
        "init_win_bytes_forward": 0,
        "init_win_bytes_backward": 0
    }
    
    attack_sample = {
        "flow_duration": 15.0,
        "total_fwd_packets": 1000,
        "total_backward_packets": 5,
        "flow_bytes_sec": 100000,
        "flow_packets_sec": 800,
        "packet_length_mean": 64,
        "packet_length_std": 5,
        "fwd_packet_length_mean": 64,
        "bwd_packet_length_mean": 64,
        "min_packet_length": 64,
        "max_packet_length": 64,
        "init_win_bytes_forward": 0,
        "init_win_bytes_backward": 0
    }
    
    # Test predictions
    for sample_name, sample in [("Normal", normal_sample), ("Attack", attack_sample)]:
        # Convert to array
        sample_array = np.array(list(sample.values())).reshape(1, -1)
        sample_scaled = scaler.transform(sample_array)
        
        # Predictions
        iso_pred = iso_forest.predict(sample_scaled)[0]
        ocsvm_pred = ocsvm.predict(sample_scaled)[0]
        iso_score = iso_forest.decision_function(sample_scaled)[0]
        ocsvm_score = ocsvm.decision_function(sample_scaled)[0]
        
        print(f"📋 {sample_name} Sample:")
        print(f"   IsolationForest: {iso_pred} (score: {iso_score:.3f})")
        print(f"   OneClassSVM: {ocsvm_pred} (score: {ocsvm_score:.3f})")
        print()

def main():
    """Main training pipeline"""
    print("🚀 Starting ML Model Training Pipeline...")
    print("=" * 50)
    
    # Step 1: Fetch raw data
    raw_data = fetch_raw_data()
    
    # Step 2: Generate synthetic training data for variety
    training_data = generate_synthetic_training_data(raw_data, num_samples=1000)
    
    # Step 3: Clean data
    clean_df = clean_data(training_data)
    
    if len(clean_df) == 0:
        print("❌ No valid data after cleaning!")
        return
    
    # Step 4: Select features
    features = select_features(clean_df)
    
    # Step 5: Save processed features
    features.to_csv("processed_features_improved.csv", index=False)
    print("💾 Saved processed features to processed_features_improved.csv")
    
    # Step 6: Scale features
    print("📏 Scaling features...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(features.values)
    
    # Step 7: Train models
    iso_forest, ocsvm = train_models_with_variety(X_scaled)
    
    # Step 8: Save models
    save_models_and_scaler(iso_forest, ocsvm, scaler)
    
    # Step 9: Test predictions
    test_model_predictions()
    
    print("=" * 50)
    print("✅ Training pipeline completed successfully!")
    print("🎯 Models should now give varied predictions")
    print("📝 Next: Restart your Flask app to load the new models")

if __name__ == "__main__":
    main()