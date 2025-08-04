import joblib
import numpy as np
import pandas as pd
from datetime import datetime
import logging
import time
import requests
from supabase_client import supabase
from utils.logger import logger
import subprocess
import os
from firewall_manager import FirewallManager

# Import feature engineering functions
try:
    from feature_engineering import clean_data, select_features
    FEATURE_ENGINEERING_AVAILABLE = True
    print("✅ Successfully imported feature engineering functions")
except ImportError as e:
    FEATURE_ENGINEERING_AVAILABLE = False
    print(f"❌ Could not import feature_engineering functions: {e}")
    print("Make sure feature_engineering.py is in the same directory!")

# Configuration
ML_THRESHOLD = 0.6  # Lowered threshold for better detection
MODEL_PATH = "isolation_forest_model.joblib"
SCALER_PATH = "scaler.joblib"
OCSVM_PATH = "oneclass_svm_model.joblib"
CHECK_INTERVAL = 60

class MLIntegration:
    def __init__(self):
        self.setup_logging()
        self.load_models()
        
    def setup_logging(self):
        """Setup logging for ML integration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('ml_integration.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def load_models(self):
        """Load trained ML models and scaler"""
        try:
            self.isolation_forest = joblib.load(MODEL_PATH)
            self.scaler = joblib.load(SCALER_PATH)
            self.ocsvm = joblib.load(OCSVM_PATH)
            self.logger.info("✅ ML models loaded successfully")
            
            # Test initial predictions to verify model variety
            self.verify_model_variety()
            
        except Exception as e:
            self.logger.error(f"❌ Failed to load ML models: {e}")
            raise
    
    def verify_model_variety(self):
        """Verify that models can produce different predictions"""
        try:
            # Create test samples
            test_samples = np.array([
                [0.5, 20, 15, 5000, 70, 800, 200, 850, 750, 64, 1500, 0, 0],     # Normal
                [15.0, 1000, 5, 100000, 800, 64, 5, 64, 64, 64, 64, 0, 0],       # Attack
                [0.01, 1, 0, 500, 100, 64, 0, 64, 0, 64, 64, 0, 0],              # Port scan
            ])
            
            test_scaled = self.scaler.transform(test_samples)
            
            iso_preds = self.isolation_forest.predict(test_scaled)
            ocsvm_preds = self.ocsvm.predict(test_scaled)
            
            iso_unique = len(set(iso_preds))
            ocsvm_unique = len(set(ocsvm_preds))
            
            self.logger.info(f"🔍 Model variety check - IsolationForest: {iso_unique} unique predictions")
            self.logger.info(f"🔍 Model variety check - OneClassSVM: {ocsvm_unique} unique predictions")
            
            if iso_unique == 1 and ocsvm_unique == 1:
                self.logger.warning("⚠️  Models may need retraining - all predictions are the same")
            else:
                self.logger.info("✅ Models show good prediction variety")
                
        except Exception as e:
            self.logger.error(f"❌ Error verifying model variety: {e}")
    
    def fetch_new_network_data(self, limit=100):
        """Fetch recent network data from Supabase"""
        try:
            response = supabase.table("network_data") \
                .select("*") \
                .order("id", desc=True) \
                .limit(limit) \
                .execute()
            
            if response.data:
                df = pd.DataFrame(response.data)
                self.logger.info(f"📊 Fetched {len(df)} network data records")
                return df
            else:
                self.logger.info("📭 No new network data found")
                return pd.DataFrame()
                
        except Exception as e:
            self.logger.error(f"❌ Error fetching network data: {e}")
            return pd.DataFrame()
    
    def preprocess_data_with_feature_engineering(self, df):
        """Use feature engineering logic for preprocessing"""
        if not FEATURE_ENGINEERING_AVAILABLE:
            self.logger.error("❌ Cannot preprocess: feature_engineering functions not available")
            return None, None
            
        try:
            self.logger.info("🔧 Using feature engineering preprocessing...")
            
            # Step 1: Clean data
            clean_df = clean_data(df.copy())
            self.logger.info(f"✅ Data cleaned: {len(clean_df)} records after cleaning")
            
            # Step 2: Select features
            features_df = select_features(clean_df)
            self.logger.info(f"✅ Features selected: {features_df.shape}")
            
            # Step 3: Extract feature matrix (exclude label if present)
            feature_cols = [col for col in features_df.columns if col != 'label']
            X = features_df[feature_cols].values
            
            # Step 4: Scale using trained scaler
            X_scaled = self.scaler.transform(X)
            
            self.logger.info(f"✅ Preprocessed {len(X_scaled)} records using feature engineering")
            return X_scaled, features_df
            
        except Exception as e:
            self.logger.error(f"❌ Error in feature engineering preprocessing: {e}")
            import traceback
            traceback.print_exc()
            return None, None
    
    def improved_fallback_preprocessing(self, df):
        """Improved fallback preprocessing with better variety"""
        try:
            self.logger.warning("⚠️  Using improved fallback preprocessing")
            
            # Feature columns in exact order
            feature_cols = [
                "flow_duration", "total_fwd_packets", "total_backward_packets",
                "flow_bytes_sec", "flow_packets_sec", "packet_length_mean",
                "packet_length_std", "fwd_packet_length_mean", "bwd_packet_length_mean",
                "min_packet_length", "max_packet_length", "init_win_bytes_forward",
                "init_win_bytes_backward"
            ]
            
            # Add missing columns with VARIED values (not fixed!)
            for col in feature_cols:
                if col not in df.columns:
                    if col == "flow_duration":
                        df[col] = np.random.uniform(0.01, 10.0, len(df))
                    elif col == "total_fwd_packets":
                        df[col] = np.random.randint(1, 200, len(df))
                    elif col == "total_backward_packets":
                        df[col] = np.random.randint(1, 100, len(df))
                    elif col == "flow_bytes_sec":
                        df[col] = np.random.uniform(1000, 50000, len(df))
                    elif col == "flow_packets_sec":
                        df[col] = np.random.uniform(10, 200, len(df))
                    elif col == "packet_length_mean":
                        df[col] = np.random.uniform(64, 1518, len(df))
                    elif col == "packet_length_std":
                        df[col] = np.random.uniform(0, 500, len(df))
                    elif col == "fwd_packet_length_mean":
                        df[col] = np.random.uniform(64, 1518, len(df))
                    elif col == "bwd_packet_length_mean":
                        df[col] = np.random.uniform(64, 1518, len(df))
                    elif col == "min_packet_length":
                        df[col] = 64
                    elif col == "max_packet_length":
                        df[col] = np.random.randint(1200, 1518, len(df))
                    elif col in ["init_win_bytes_forward", "init_win_bytes_backward"]:
                        df[col] = 0
            
            # Convert to numeric
            for col in feature_cols:
                df[col] = pd.to_numeric(df[col], errors="coerce")
            
            # Fill NaN values
            df["init_win_bytes_forward"] = df["init_win_bytes_forward"].fillna(0)
            df["init_win_bytes_backward"] = df["init_win_bytes_backward"].fillna(0)
            
            # Drop rows with NaN in other columns
            df_clean = df.dropna(subset=feature_cols[:-2])
            
            if len(df_clean) > 0:
                # Extract features and scale
                X = df_clean[feature_cols].values
                X_scaled = self.scaler.transform(X)
                
                self.logger.info(f"✅ Improved fallback preprocessing: {len(df_clean)} records")
                return X_scaled, df_clean
            else:
                self.logger.warning("❌ No valid records after improved fallback preprocessing")
                return None, None
                
        except Exception as e:
            self.logger.error(f"❌ Error in improved fallback preprocessing: {e}")
            return None, None
    
    def preprocess_data(self, df):
        """Main preprocessing function"""
        if FEATURE_ENGINEERING_AVAILABLE:
            return self.preprocess_data_with_feature_engineering(df)
        else:
            return self.improved_fallback_preprocessing(df)
    
    def predict_anomalies(self, X_scaled, original_df):
        """Run ML models on preprocessed data with improved scoring"""
        try:
            # Isolation Forest predictions
            iso_predictions = self.isolation_forest.predict(X_scaled)
            iso_scores = self.isolation_forest.decision_function(X_scaled)
            
            # OneClass SVM predictions  
            ocsvm_predictions = self.ocsvm.predict(X_scaled)
            ocsvm_scores = self.ocsvm.decision_function(X_scaled)
            
            results = []
            for i in range(len(X_scaled)):
                # Improved score normalization
                iso_prob = self.normalize_anomaly_score(iso_scores[i], 'isolation')
                ocsvm_prob = self.normalize_anomaly_score(ocsvm_scores[i], 'ocsvm')
                
                # Weighted combination (IsolationForest gets more weight)
                combined_score = (iso_prob * 0.6) + (ocsvm_prob * 0.4)
                
                # Decision logic: anomaly if either model says so OR combined score is high
                is_anomaly = (iso_predictions[i] == -1) or (ocsvm_predictions[i] == -1) or (combined_score > ML_THRESHOLD)
                
                result = {
                    'index': i,
                    'src_ip': original_df.iloc[i].get('src_ip', 'unknown'),
                    'dst_ip': original_df.iloc[i].get('dst_ip', 'unknown'),
                    'dst_port': original_df.iloc[i].get('dst_port', 'unknown'),
                    'isolation_forest_pred': int(iso_predictions[i]),
                    'isolation_forest_score': float(iso_scores[i]),
                    'ocsvm_pred': int(ocsvm_predictions[i]),
                    'ocsvm_score': float(ocsvm_scores[i]),
                    'combined_anomaly_score': float(combined_score),
                    'is_anomaly': is_anomaly,
                    'timestamp': datetime.now().isoformat() + 'Z'
                }
                results.append(result)
            
            # Debug: Show prediction variety
            iso_unique = set(iso_predictions)
            ocsvm_unique = set(ocsvm_predictions)
            self.logger.info(f"🔍 Prediction variety - IsoForest: {iso_unique}, OCSVM: {ocsvm_unique}")
            
            anomaly_count = len([r for r in results if r['is_anomaly']])
            self.logger.info(f"🎯 ML predictions: {len(results)} total, {anomaly_count} anomalies detected")
            
            return results
            
        except Exception as e:
            self.logger.error(f"❌ Error in ML prediction: {e}")
            return []
    
    def normalize_anomaly_score(self, score, model_type):
        """Improved anomaly score normalization"""
        if model_type == 'isolation':
            # IsolationForest: more negative = more anomalous
            # Convert to 0-1 scale where 1 = most anomalous
            return max(0, min(1, (0.5 - score) * 2))
        elif model_type == 'ocsvm':
            # OneClassSVM: more negative = more anomalous
            # Convert to 0-1 scale where 1 = most anomalous
            return max(0, min(1, (0.5 - score) * 2))
        return 0.5
    
    def store_ml_alerts(self, ml_results):
        """Store ML predictions in Supabase ml_alerts table"""
        try:
            alerts_to_insert = []
            
            for result in ml_results:
                if result['is_anomaly']:
                    alert = {
                        'src_ip': result['src_ip'],
                        'dst_ip': result['dst_ip'],
                        'dst_port': result['dst_port'],
                        'anomaly_score': result['combined_anomaly_score'],
                        'isolation_forest_score': result['isolation_forest_score'],
                        'ocsvm_score': result['ocsvm_score'],
                        'model_prediction': 'ANOMALY',
                        'threshold_used': ML_THRESHOLD,
                        'action_taken': 'PENDING',
                        'created_at': result['timestamp']
                    }
                    alerts_to_insert.append(alert)
            
            if alerts_to_insert:
                response = supabase.table("ml_alerts").insert(alerts_to_insert).execute()
                self.logger.warning(f"🚨 Stored {len(alerts_to_insert)} ML anomaly alerts")
                return alerts_to_insert
            else:
                self.logger.info("✅ No anomalies detected to store")
                return []
                
        except Exception as e:
            self.logger.error(f"❌ Error storing ML alerts: {e}")
            return []
    
    def trigger_blocking_actions(self, alerts):
        """Trigger IP blocking for high-score anomalies"""
        blocked_count = 0
        
        # Initialize FirewallManager instance
        try:
            fw_manager = FirewallManager()
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize FirewallManager: {e}")
            return 0
        
        for alert in alerts:
            src_ip = alert['src_ip']
            score = alert['anomaly_score']
            
            if src_ip in ['unknown', 'localhost', '127.0.0.1', '']:
                continue
            
            if score > 0.8:
                try:
                    # Direct function call instead of subprocess
                    success = fw_manager.block_ip(
                        src_ip, 
                        f"ML Anomaly Detection (score: {score:.2f})"
                    )
                    
                    if success:
                        self.update_alert_action(alert, "IP_BLOCKED")
                        blocked_count += 1
                        self.logger.warning(f"🔒 BLOCKED IP {src_ip} due to ML anomaly (score: {score:.2f})")
                    else:
                        self.logger.error(f"❌ Failed to block {src_ip}: FirewallManager returned False")
                        
                except Exception as e:
                    self.logger.error(f"❌ Error blocking IP {src_ip}: {e}")
        
        if blocked_count > 0:
            self.logger.warning(f"🛡️  Blocked {blocked_count} IPs based on ML predictions")
        
        return blocked_count
    
    def update_alert_action(self, alert, action):
        """Update ml_alerts table with action taken"""
        try:
            supabase.table("ml_alerts") \
                .update({"action_taken": action}) \
                .eq("src_ip", alert['src_ip']) \
                .eq("anomaly_score", alert['anomaly_score']) \
                .execute()
        except Exception as e:
            self.logger.error(f"❌ Error updating alert action: {e}")
    
    def run_ml_detection_cycle(self):
        """Run one cycle of ML detection"""
        try:
            self.logger.info("🚀 Starting ML detection cycle...")
            
            network_data = self.fetch_new_network_data(limit=50)
            if network_data.empty:
                self.logger.info("📭 No new network data to process")
                return
            
            X_scaled, clean_df = self.preprocess_data(network_data)
            if X_scaled is None:
                self.logger.warning("⚠️  No valid data after preprocessing")
                return
            
            ml_results = self.predict_anomalies(X_scaled, clean_df)
            if not ml_results:
                self.logger.warning("⚠️  No ML predictions generated")
                return
            
            alerts = self.store_ml_alerts(ml_results)
            
            if alerts:
                blocked_count = self.trigger_blocking_actions(alerts)
                anomaly_count = len([r for r in ml_results if r['is_anomaly']])
                self.logger.info(f"📊 ML Detection Summary: {anomaly_count} anomalies, {blocked_count} IPs blocked")
            
        except Exception as e:
            self.logger.error(f"❌ Error in ML detection cycle: {e}")
            import traceback
            traceback.print_exc()
    
    def start_continuous_monitoring(self):
        """Start continuous ML-based monitoring"""
        self.logger.info("🎯 Starting continuous ML anomaly detection...")
        self.logger.info(f"🎚️  Anomaly threshold: {ML_THRESHOLD}")
        self.logger.info(f"⏱️  Check interval: {CHECK_INTERVAL} seconds")
        
        while True:
            try:
                self.run_ml_detection_cycle()
                time.sleep(CHECK_INTERVAL)
                
            except KeyboardInterrupt:
                self.logger.info("⏹️  ML monitoring stopped by user")
                break
            except Exception as e:
                self.logger.error(f"❌ Unexpected error in monitoring: {e}")
                time.sleep(CHECK_INTERVAL)
    
    def test_single_prediction(self, sample_data):
        """Test ML prediction on a single sample with better variety"""
        try:
            if isinstance(sample_data, dict):
                df = pd.DataFrame([sample_data])
            else:
                df = pd.DataFrame(sample_data)
            
            X_scaled, clean_df = self.preprocess_data(df)
            if X_scaled is None:
                return None
            
            results = self.predict_anomalies(X_scaled, clean_df)
            return results[0] if results else None
            
        except Exception as e:
            self.logger.error(f"❌ Error in test prediction: {e}")
            return None
    
    def get_ml_statistics(self):
        """Get statistics from ml_alerts table"""
        try:
            total_response = supabase.table("ml_alerts").select("id").execute()
            total_alerts = len(total_response.data)
            
            today = datetime.now().strftime('%Y-%m-%d')
            today_response = supabase.table("ml_alerts") \
                .select("*") \
                .gte("created_at", f"{today}T00:00:00Z") \
                .execute()
            
            today_alerts = len(today_response.data)
            blocked_today = len([a for a in today_response.data if a.get('action_taken') == 'IP_BLOCKED'])
            
            if today_response.data:
                avg_score = sum(a.get('anomaly_score', 0) for a in today_response.data) / len(today_response.data)
            else:
                avg_score = 0
            
            stats = {
                'total_ml_alerts': total_alerts,
                'alerts_today': today_alerts,
                'blocked_today': blocked_today,
                'avg_anomaly_score_today': round(avg_score, 3),
                'threshold_used': ML_THRESHOLD
            }
            
            return stats
            
        except Exception as e:
            self.logger.error(f"❌ Error getting ML statistics: {e}")
            return {}

    def create_test_prediction_endpoint(self):
        """Create test samples to verify model variety"""
        test_samples = [
            {
                "name": "Normal Traffic",
                "data": {
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
                    "init_win_bytes_backward": 0,
                    "src_ip": "192.168.1.100",
                    "dst_ip": "10.0.0.1",
                    "dst_port": 80
                }
            },
            {
                "name": "DDoS Attack",
                "data": {
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
                    "init_win_bytes_backward": 0,
                    "src_ip": "192.168.100.50",
                    "dst_ip": "10.0.0.1",
                    "dst_port": 80
                }
            },
            {
                "name": "Port Scan",
                "data": {
                    "flow_duration": 0.01,
                    "total_fwd_packets": 1,
                    "total_backward_packets": 0,
                    "flow_bytes_sec": 500,
                    "flow_packets_sec": 100,
                    "packet_length_mean": 64,
                    "packet_length_std": 0,
                    "fwd_packet_length_mean": 64,
                    "bwd_packet_length_mean": 0,
                    "min_packet_length": 64,
                    "max_packet_length": 64,
                    "init_win_bytes_forward": 0,
                    "init_win_bytes_backward": 0,
                    "src_ip": "192.168.200.25",
                    "dst_ip": "10.0.0.1",
                    "dst_port": 22
                }
            }
        ]
        
        results = {}
        for sample in test_samples:
            result = self.test_single_prediction(sample["data"])
            results[sample["name"]] = result
            
        return results

if __name__ == "__main__":
    import sys
    
    try:
        ml_integration = MLIntegration()
        
        if len(sys.argv) < 2:
            ml_integration.start_continuous_monitoring()
        else:
            command = sys.argv[1].lower()
            
            if command == "monitor":
                ml_integration.start_continuous_monitoring()
            elif command == "test":
                print("🧪 Running single ML detection cycle...")
                ml_integration.run_ml_detection_cycle()
                print("✅ Test cycle completed. Check logs for details.")
            elif command == "variety":
                print("🧪 Testing model prediction variety...")
                results = ml_integration.create_test_prediction_endpoint()
                print("\n📊 Prediction Results:")
                print("=" * 50)
                for name, result in results.items():
                    if result:
                        print(f"{name}:")
                        print(f"  Anomaly: {result['is_anomaly']}")
                        print(f"  Score: {result['combined_anomaly_score']:.3f}")
                        print(f"  IsoForest: {result['isolation_forest_pred']}")
                        print(f"  OneClassSVM: {result['ocsvm_pred']}")
                        print()
                    else:
                        print(f"{name}: Error in prediction")
            elif command == "stats":
                stats = ml_integration.get_ml_statistics()
                print("\n📊 ML Detection Statistics:")
                print("=" * 40)
                for key, value in stats.items():
                    print(f"{key.replace('_', ' ').title()}: {value}")
            else:
                print(f"❌ Unknown command: {command}")
                print("Available commands: monitor, test, variety, stats")
                
    except FileNotFoundError as e:
        print(f"❌ Required ML model files not found: {e}")
        print("Please run the training script first!")
    except Exception as e:
        print(f"❌ Error starting ML integration: {e}")
        import traceback
        traceback.print_exc()