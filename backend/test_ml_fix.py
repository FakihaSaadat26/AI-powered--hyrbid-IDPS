#!/usr/bin/env python3
"""
Test script to verify ML models are working properly
"""

import requests
import json
import time

# Your Flask app URL
BASE_URL = "http://localhost:5000"

def test_health_check():
    """Test if the API is running"""
    print("🔍 Testing API health...")
    try:
        response = requests.get(f"{BASE_URL}/")
        if response.status_code == 200:
            data = response.json()
            print("✅ API is running!")
            print(f"   Simple ML Available: {data['services']['simple_ml']}")
            print(f"   Advanced ML Available: {data['ml_details']['advanced_ml_available']}")
            return True
        else:
            print(f"❌ API returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error connecting to API: {e}")
        return False

def test_model_variety():
    """Test the built-in model variety endpoint"""
    print("\n🧪 Testing model variety...")
    try:
        response = requests.get(f"{BASE_URL}/test-model-variety")
        if response.status_code == 200:
            data = response.json()
            print("✅ Model variety test results:")
            print(f"   Normal prediction: {data['analysis']['normal_prediction']}")
            print(f"   Attack prediction: {data['analysis']['attack_prediction']}")
            print(f"   Predictions different: {data['analysis']['predictions_different']}")
            print(f"   Model working properly: {data['analysis']['model_working_properly']}")
            
            if data['analysis']['model_working_properly']:
                print("🎯 Models are working correctly!")
                return True
            else:
                print("⚠️  Models may need retraining")
                return False
        else:
            print(f"❌ Model variety test failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error testing model variety: {e}")
        return False

def test_ml_predictions():
    """Test ML predictions with different types of traffic"""
    print("\n🧪 Testing ML predictions...")
    
    # Test samples
    test_samples = [
        {
            "name": "Normal Web Traffic",
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
            "name": "Suspected DDoS Attack",
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
            "name": "Port Scan Activity",
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
        },
        {
            "name": "Slow HTTP Attack",
            "data": {
                "flow_duration": 120.0,
                "total_fwd_packets": 3,
                "total_backward_packets": 1,
                "flow_bytes_sec": 50,
                "flow_packets_sec": 0.5,
                "packet_length_mean": 200,
                "packet_length_std": 50,
                "fwd_packet_length_mean": 250,
                "bwd_packet_length_mean": 100,
                "min_packet_length": 64,
                "max_packet_length": 400,
                "init_win_bytes_forward": 0,
                "init_win_bytes_backward": 0,
                "src_ip": "192.168.50.75",
                "dst_ip": "10.0.0.1",
                "dst_port": 80
            }
        }
    ]
    
    results = []
    for sample in test_samples:
        print(f"\n📋 Testing: {sample['name']}")
        
        try:
            # Test simple ML endpoint
            response = requests.post(f"{BASE_URL}/ml-predict", json=sample["data"])
            
            if response.status_code == 200:
                data = response.json()
                result = {
                    "name": sample["name"],
                    "prediction": data.get("prediction"),
                    "anomaly_score": data.get("anomaly_score"),
                    "is_anomaly": data.get("is_anomaly"),
                    "threat_detected": data.get("threat_detected")
                }
                
                print(f"   Prediction: {result['prediction']} ({'Anomaly' if result['prediction'] == -1 else 'Normal'})")
                print(f"   Anomaly Score: {result['anomaly_score']:.3f}")
                print(f"   Threat Detected: {result['threat_detected']}")
                
                results.append(result)
            else:
                print(f"   ❌ Error: {response.status_code}")
                print(f"   Response: {response.text}")
                
        except Exception as e:
            print(f"   ❌ Error: {e}")
    
    return results

def test_advanced_ml():
    """Test advanced ML endpoint if available"""
    print("\n🔬 Testing advanced ML endpoint...")
    
    test_data = {
        "flow_duration": 10.0,
        "total_fwd_packets": 500,
        "total_backward_packets": 10,
        "flow_bytes_sec": 50000,
        "flow_packets_sec": 400,
        "src_ip": "192.168.1.200",
        "dst_ip": "10.0.0.1",
        "dst_port": 80
    }
    
    try:
        response = requests.post(f"{BASE_URL}/ml-predict-advanced", json=test_data)
        
        if response.status_code == 200:
            data = response.json()
            print("✅ Advanced ML endpoint working!")
            print(f"   Anomaly Detected: {data.get('anomaly_detected')}")
            print(f"   Anomaly Score: {data.get('anomaly_score'):.3f}")
            return True
        else:
            print(f"⚠️  Advanced ML endpoint not available: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Error testing advanced ML: {e}")
        return False

def analyze_results(results):
    """Analyze the test results"""
    print("\n📊 ANALYSIS:")
    print("=" * 50)
    
    if not results:
        print("❌ No results to analyze")
        return
    
    # Check if we got variety in predictions
    predictions = [r["prediction"] for r in results]
    unique_predictions = set(predictions)
    
    print(f"Total tests: {len(results)}")
    print(f"Unique predictions: {len(unique_predictions)} {unique_predictions}")
    
    # Expected results
    expected_anomalies = ["Suspected DDoS Attack", "Port Scan Activity", "Slow HTTP Attack"]
    expected_normal = ["Normal Web Traffic"]
    
    correct_anomalies = 0
    correct_normal = 0
    
    for result in results:
        if result["name"] in expected_anomalies and result["is_anomaly"]:
            correct_anomalies += 1
        elif result["name"] in expected_normal and not result["is_anomaly"]:
            correct_normal += 1
    
    print(f"Correctly detected anomalies: {correct_anomalies}/{len(expected_anomalies)}")
    print(f"Correctly detected normal: {correct_normal}/{len(expected_normal)}")
    
    if len(unique_predictions) > 1:
        print("✅ Model is giving varied predictions!")
    else:
        print("❌ Model is giving same prediction for all inputs")
        print("   This suggests the model needs retraining")
    
    if correct_anomalies >= 2 and correct_normal >= 1:
        print("✅ Model appears to be working correctly!")
    else:
        print("⚠️  Model may need fine-tuning")

def main():
    """Main test function"""
    print("🚀 Testing ML Models and API")
    print("=" * 50)
    
    # Test 1: Health check
    if not test_health_check():
        print("❌ API not available. Please start your Flask app first.")
        return
    
    # Test 2: Model variety
    test_model_variety()
    
    # Test 3: ML predictions
    results = test_ml_predictions()
    
    # Test 4: Advanced ML (if available)
    test_advanced_ml()
    
    # Test 5: Analyze results
    analyze_results(results)
    
    print("\n" + "=" * 50)
    print("🏁 Testing completed!")
    print("\nIf you see varied predictions and correct anomaly detection,")
    print("your models are working properly for Week 4 dashboard tasks!")

if __name__ == "__main__":
    main()