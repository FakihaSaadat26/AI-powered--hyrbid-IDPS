# app.py
from datetime import datetime
from flask import Flask, request, jsonify
import pandas as pd
import traceback

# Import with error handling
try:
    from signature.signature_engine import check_payload_against_signatures
    SIGNATURE_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Signature engine not available: {e}")
    SIGNATURE_AVAILABLE = False

try:
    from rules.flow_rule_engine import detect_ddos_bursts, detect_failed_login_bursts, detect_syn_flood_flows
    RULES_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Rule engine not available: {e}")
    RULES_AVAILABLE = False

try:
    from ml_integration import MLIntegration
    ML_AVAILABLE = True
except ImportError as e:
    print(f"Warning: ML integration not available: {e}")
    ML_AVAILABLE = False

# Laiba's feature engineering import for simple ML endpoint
try:
    import joblib
    import numpy as np
    from feature_engineering import clean_data, select_features
    # Load ML model and scaler at startup
    iso_forest = joblib.load('isolation_forest_model.joblib')
    scaler = joblib.load('scaler.joblib')
    SIMPLE_ML_AVAILABLE = True
    print("✅ Simple ML models loaded successfully")
except Exception as e:
    print(f"Warning: Simple ML models not available: {e}")
    iso_forest = None
    scaler = None
    SIMPLE_ML_AVAILABLE = False

try:
    from supabase_client import supabase
    SUPABASE_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Supabase client not available: {e}")
    SUPABASE_AVAILABLE = False

try:
    from utils.logger import logger
    LOGGER_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Logger not available: {e}")
    LOGGER_AVAILABLE = False
    # Fallback logger
    import logging
    logger = logging.getLogger(__name__)

app = Flask(__name__)

# Initialize ML Integration with better error handling
ml_integration = None
if ML_AVAILABLE:
    try:
        ml_integration = MLIntegration()
        if LOGGER_AVAILABLE:
            logger.info("✅ ML Integration initialized successfully")
        else:
            print("✅ ML Integration initialized successfully")
    except FileNotFoundError as e:
        ml_integration = None
        if LOGGER_AVAILABLE:
            logger.error(f"❌ ML models not found: {e}")
        else:
            print(f"❌ ML models not found: {e}")
        print("Make sure Laiba has trained the models first!")
    except Exception as e:
        ml_integration = None
        if LOGGER_AVAILABLE:
            logger.error(f"❌ Failed to initialize ML Integration: {e}")
        else:
            print(f"❌ Failed to initialize ML Integration: {e}")

# --- Basic health check endpoint ---
@app.route("/", methods=["GET"])
def health_check():
    """Enhanced health check endpoint"""
    ml_status = "loaded" if ml_integration else "not_loaded"
    ml_models_exist = SIMPLE_ML_AVAILABLE
    
    return jsonify({
        "status": "AI-Powered Hybrid IDPS Backend is Running!",
        "services": {
            "signature_engine": SIGNATURE_AVAILABLE,
            "rule_engine": RULES_AVAILABLE,
            "ml_integration": ml_status,
            "simple_ml": ml_models_exist,
            "supabase": SUPABASE_AVAILABLE,
            "logger": LOGGER_AVAILABLE
        },
        "ml_details": {
            "advanced_ml_available": ml_integration is not None,
            "simple_ml_available": SIMPLE_ML_AVAILABLE,
            "models_loaded": ["isolation_forest", "scaler"] if SIMPLE_ML_AVAILABLE else []
        }
    }), 200

# --- Test endpoint ---
@app.route("/test", methods=["GET"])
def test_endpoint():
    """Simple test endpoint"""
    return jsonify({"message": "API is working!", "status": "success"}), 200

# --- Enhanced simple ML prediction endpoint ---
@app.route("/ml-predict", methods=["POST"])
def ml_predict():
    """Enhanced simple ML prediction using Laiba's preprocessing"""
    if not SIMPLE_ML_AVAILABLE:
        return jsonify({
            "error": "ML models not available", 
            "suggestion": "Make sure Laiba has trained the models"
        }), 503
    
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data received"}), 400
    
    try:
        # Option 1: If features array is provided directly
        if "features" in data:
            features = np.array(data["features"]).reshape(1, -1)
            features_scaled = scaler.transform(features)
            prediction = iso_forest.predict(features_scaled)[0]
            score = iso_forest.decision_function(features_scaled)[0]
            
        # Option 2: If raw network data is provided, use Laiba's preprocessing
        else:
            df = pd.DataFrame([data])
            clean_df = clean_data(df)
            features_df = select_features(clean_df)
            feature_cols = [col for col in features_df.columns if col != 'label']
            X = features_df[feature_cols].values
            X_scaled = scaler.transform(X)
            prediction = iso_forest.predict(X_scaled)[0]
            score = iso_forest.decision_function(X_scaled)[0]
        
        # Ensure prediction is cleanly handled
        is_anomaly = bool(prediction == -1)
        severity = "High" if is_anomaly else "Low"
        threat_type = "ML Anomaly" if is_anomaly else "Normal"
        
        # Store result in Supabase alerts table
        if SUPABASE_AVAILABLE:
            supabase.table("alerts").insert({
                "src_ip": data.get("src_ip", "unknown"),
                "threat_type": threat_type,
                "severity": severity,
                "action_taken": "None",
                "detected_by": "simple_ml_model",
                "timestamp": data.get("timestamp", None)
            }).execute()
            
            if LOGGER_AVAILABLE:
                logger.info(f"Simple ML prediction stored: {prediction} for IP {data.get('src_ip', 'unknown')}")
        
        return jsonify({
            "prediction": int(prediction),
            "anomaly_score": float(score),
            "is_anomaly": is_anomaly,
            "threat_detected": is_anomaly,
            "src_ip": data.get("src_ip", "unknown"),
            "processing_method": "features" if "features" in data else "laiba_preprocessing"
        }), 200
        
    except Exception as e:
        if LOGGER_AVAILABLE:
            logger.error(f"Error in simple ML prediction: {e}")
        print(f"Error in simple ML prediction: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# --- Advanced ML-based detection endpoint ---
@app.route("/ml-predict-advanced", methods=["POST"])
def ml_predict_endpoint():
    """Advanced ML prediction endpoint using updated MLIntegration"""
    if not ml_integration:
        return jsonify({
            "error": "Advanced ML models not available",
            "suggestion": "Check if ML models are properly trained and loaded"
        }), 503
    
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data received"}), 400
    
    try:
        result = ml_integration.test_single_prediction(data)
        
        if result:
            # Convert numpy/pandas types to Python native types
            clean_result = {}
            for key, value in result.items():
                if hasattr(value, 'item'):
                    clean_result[key] = value.item()
                elif pd.isna(value):
                    clean_result[key] = None
                elif isinstance(value, (np.bool_, bool)):
                    clean_result[key] = bool(value)
                elif isinstance(value, (np.integer, np.floating)):
                    clean_result[key] = value.item()
                else:
                    clean_result[key] = value
            
            is_anomaly = bool(clean_result.get('is_anomaly', False))
            
            # Store in ml_alerts if anomaly detected
            if is_anomaly and SUPABASE_AVAILABLE:
            # Patch IP/Port if missing
                for field in ["src_ip", "dst_ip", "dst_port"]:
                    if not clean_result.get(field) or clean_result.get(field) == "unknown":
                        clean_result[field] = data.get(field, None)

            alert = {
                'src_ip': clean_result.get('src_ip') or None,
                'dst_ip': clean_result.get('dst_ip') or None,
                'dst_port': clean_result.get('dst_port') if isinstance(clean_result.get('dst_port'), int) else None,
                'anomaly_score': float(clean_result.get('combined_anomaly_score', 0)),
                'isolation_forest_score': float(clean_result.get('isolation_forest_score', 0)),
                'ocsvm_score': float(clean_result.get('ocsvm_score', 0)),
                'model_prediction': 'ANOMALY',
                'action_taken': 'API_DETECTED',
                'created_at': clean_result.get('timestamp') or None
            }

            supabase.table("ml_alerts").insert([alert]).execute()
            if LOGGER_AVAILABLE:
                logger.warning(f"🚨 Advanced ML API detected anomaly from {clean_result.get('src_ip', 'unknown')}")

            return jsonify({
                "status": "prediction_complete",
                "anomaly_detected": is_anomaly,
                "anomaly_score": float(clean_result.get('combined_anomaly_score', 0)),
                "model_scores": {
                    "isolation_forest": float(clean_result.get('isolation_forest_score', 0)),
                    "ocsvm": float(clean_result.get('ocsvm_score', 0))
                },
                "details": clean_result,
                "processing": "laiba_preprocessing_used"
            }), 200
        else:
            return jsonify({
                "error": "Prediction failed", 
                "suggestion": "Check input data format or model availability"
            }), 500
            
    except Exception as e:
        if LOGGER_AVAILABLE:
            logger.error(f"Error in advanced ML prediction endpoint: {e}")
        print(f"Error in advanced ML prediction endpoint: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# --- ML statistics endpoint ---
@app.route("/ml-stats", methods=["GET"])  
def ml_stats_endpoint():
    """Get ML detection statistics"""
    if not ml_integration:
        return jsonify({
            "error": "Advanced ML models not available",
            "suggestion": "Initialize ML integration first"
        }), 503
    
    try:
        stats = ml_integration.get_ml_statistics()
        return jsonify({
            "status": "success",
            "ml_statistics": stats,
            "note": "Statistics from advanced ML integration using Laiba's preprocessing"
        }), 200
        
    except Exception as e:
        if LOGGER_AVAILABLE:
            logger.error(f"Error getting ML statistics: {e}")
        print(f"Error getting ML statistics: {e}")
        return jsonify({"error": str(e)}), 500

# --- Trigger ML detection cycle endpoint ---
@app.route("/run-ml-detection", methods=["POST"])
def run_ml_detection_endpoint():
    """Manually trigger ML detection cycle"""
    if not ml_integration:
        return jsonify({
            "error": "Advanced ML models not available",
            "suggestion": "Initialize ML integration first"
        }), 503
    
    try:
        # Run detection cycle
        ml_integration.run_ml_detection_cycle()
        
        # Get updated stats
        stats = ml_integration.get_ml_statistics()
        
        return jsonify({
            "status": "ML detection cycle completed",
            "message": "Used Laiba's preprocessing for consistent results",
            "statistics": stats
        }), 200
        
    except Exception as e:
        if LOGGER_AVAILABLE:
            logger.error(f"Error running ML detection cycle: {e}")
        print(f"Error running ML detection cycle: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# --- Test model variety endpoint ---
@app.route("/test-model-variety", methods=["GET"])
def test_model_variety():
    """Test if models are giving different predictions"""
    if not SIMPLE_ML_AVAILABLE:
        return jsonify({"error": "Simple ML models not available"}), 503
    
    try:
        # Create test samples with different characteristics
        normal_sample = {
            "flow_duration": 0.1,
            "total_fwd_packets": 10,
            "total_backward_packets": 5,
            "flow_bytes_sec": 5000,
            "flow_packets_sec": 50,
            "packet_length_mean": 1000,
            "packet_length_std": 100,
            "fwd_packet_length_mean": 1000,
            "bwd_packet_length_mean": 900,
            "min_packet_length": 64,
            "max_packet_length": 1518,
            "init_win_bytes_forward": 0,
            "init_win_bytes_backward": 0
        }
        
        attack_sample = {
            "flow_duration": 10.0,
            "total_fwd_packets": 1000,
            "total_backward_packets": 10,
            "flow_bytes_sec": 100000,
            "flow_packets_sec": 500,
            "packet_length_mean": 64,
            "packet_length_std": 10,
            "fwd_packet_length_mean": 64,
            "bwd_packet_length_mean": 64,
            "min_packet_length": 64,
            "max_packet_length": 64,
            "init_win_bytes_forward": 0,
            "init_win_bytes_backward": 0
        }
        
        # Test predictions
        results = {}
        
        for sample_name, sample_data in [("normal", normal_sample), ("attack", attack_sample)]:
            df = pd.DataFrame([sample_data])
            clean_df = clean_data(df)
            features_df = select_features(clean_df)
            
            # Get only numeric columns, exclude label if present
            feature_cols = [col for col in features_df.columns if col != 'label']
            if not feature_cols:
                # If no feature columns found, use all columns
                feature_cols = features_df.columns.tolist()
            
            X = features_df[feature_cols].values
            X_scaled = scaler.transform(X)
            
            prediction = iso_forest.predict(X_scaled)[0]
            score = iso_forest.decision_function(X_scaled)[0]
            
            results[sample_name] = {
                "prediction": int(prediction),
                "score": float(score),
                "is_anomaly": prediction == -1
            }
        
        return jsonify({
            "status": "Model variety test completed",
            "results": results,
            "analysis": {
                "predictions_different": results["normal"]["prediction"] != results["attack"]["prediction"],
                "normal_prediction": results["normal"]["prediction"],
                "attack_prediction": results["attack"]["prediction"],
                "model_working_properly": results["normal"]["prediction"] == 1 and results["attack"]["prediction"] == -1
            }
        }), 200
        
    except Exception as e:
        print(f"Error in model variety test: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
    
# --- Signature-based detection endpoint ---
@app.route("/scan", methods=["POST"])
def scan_endpoint():
    if not SIGNATURE_AVAILABLE:
        return jsonify({"error": "Signature engine not available"}), 503
    
    data = request.get_json()

    if not data:
        if LOGGER_AVAILABLE:
            logger.warning("Received request with no JSON data.")
        else:
            print("Received request with no JSON data.")
        return jsonify({"error": "No JSON data received"}), 400

    payload = data.get("payload", "")
    src_ip = data.get("src_ip", "unknown")
    
    if LOGGER_AVAILABLE:
        logger.info(f"Received scan request from IP: {src_ip}")
    else:
        print(f"Received scan request from IP: {src_ip}")

    try:
        result = check_payload_against_signatures(payload)

        if result:
            if LOGGER_AVAILABLE:
                logger.warning(f"Threat detected from IP {src_ip}: {result['threat']} (Severity: {result['severity']})")
            else:
                print(f"Threat detected from IP {src_ip}: {result['threat']} (Severity: {result['severity']})")

            if SUPABASE_AVAILABLE:
                supabase.table("alerts").insert({
                    "src_ip": src_ip,
                    "threat_type": result["threat"],
                    "severity": result["severity"],
                    "action_taken": data.get("action_taken", "none"),  # lowercase or default string
                    "detected_by": "signature",
                    "timestamp": data.get("timestamp") or datetime.utcnow().isoformat()
                }).execute()
                
                if LOGGER_AVAILABLE:
                    logger.info("Threat info saved to Supabase.")
                else:
                    print("Threat info saved to Supabase.")

            return jsonify({
                "status": "threat_detected",
                "details": result
            }), 200
        else:
            if LOGGER_AVAILABLE:
                logger.info(f"No threat detected from IP {src_ip}. Payload clean.")
            else:
                print(f"No threat detected from IP {src_ip}. Payload clean.")
            return jsonify({"status": "clean"}), 200
    
    except Exception as e:
        if LOGGER_AVAILABLE:
            logger.error(f"Error in scan endpoint: {e}")
        print(f"Error in scan endpoint: {e}")
        return jsonify({"error": str(e)}), 500

# --- Rule-based detection endpoint ---
@app.route("/run-rule-engine", methods=["GET"])
def run_rule_engine():
    if not RULES_AVAILABLE:
        return jsonify({"error": "Rule engine not available"}), 503
    
    try:
        syn_alerts = detect_syn_flood_flows()
        login_alerts = detect_failed_login_bursts()
        ddos_alerts = detect_ddos_bursts()

        total_alerts = syn_alerts + login_alerts + ddos_alerts

        return jsonify({
            "status": "Rule engine detection completed",
            "total_alerts_generated": len(total_alerts),
            "alerts": total_alerts
        }), 200
    
    except Exception as e:
        if LOGGER_AVAILABLE:
            logger.error(f"Error in rule engine: {e}")
        print(f"Error in rule engine: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    print("🚀 Starting AI-Powered Hybrid IDPS Backend...")
    print(f"Simple ML Available: {SIMPLE_ML_AVAILABLE}")
    print(f"Advanced ML Available: {ml_integration is not None}")
    print("=" * 50)
    
    if SIMPLE_ML_AVAILABLE:
        print("✅ Simple ML: Using preprocessing")
    else:
        print("❌ Simple ML: Not available")
        
    if ml_integration:
        print("✅ Advanced ML: Using updated ML integration")
    else:
        print("❌ Advanced ML: Not available")
        
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=5000)