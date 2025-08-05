#!/usr/bin/env python3
"""
Definitive IP Blocking Test Script
This script tests IP blocking with values that should definitely trigger blocking.
"""

import requests
import json
import time
from datetime import datetime

# Configuration
API_BASE_URL = "http://localhost:5050"

def test_definitive_blocking():
    """Test IP blocking with definitive high scores"""
    print("🚫 Testing Definitive IP Blocking...")
    
    # Test with values that should definitely trigger high anomaly scores
    definitive_anomaly_traffic = {
        "flow_duration": 0.001,  # Extremely short duration
        "total_fwd_packets": 50000,  # Massive packet count
        "total_backward_packets": 0,  # No response packets
        "flow_bytes_sec": 5000000,  # Extremely high bandwidth
        "flow_packets_sec": 10000,  # Very high packet rate
        "packet_length_mean": 8,  # Extremely small packets
        "packet_length_std": 0,  # No variation
        "fwd_packet_length_mean": 8,
        "bwd_packet_length_mean": 0,
        "min_packet_length": 8,
        "max_packet_length": 8,
        "init_win_bytes_forward": 0,
        "init_win_bytes_backward": 0,
        "src_ip": "192.168.1.999",  # Test IP for blocking
        "timestamp": datetime.utcnow().isoformat()
    }
    
    print(f"🔍 Testing with IP: {definitive_anomaly_traffic['src_ip']}")
    print(f"📊 Extreme traffic characteristics:")
    print(f"   - Duration: {definitive_anomaly_traffic['flow_duration']}s (extremely short)")
    print(f"   - Packets: {definitive_anomaly_traffic['total_fwd_packets']} forward, {definitive_anomaly_traffic['total_backward_packets']} backward")
    print(f"   - Bandwidth: {definitive_anomaly_traffic['flow_bytes_sec']} bytes/sec (extremely high)")
    print(f"   - Packet size: {definitive_anomaly_traffic['packet_length_mean']} bytes (extremely small)")
    
    # Test ML prediction
    response = requests.post(f"{API_BASE_URL}/ml-predict", json=definitive_anomaly_traffic)
    if response.status_code == 200:
        result = response.json()
        score = result.get('anomaly_score', 0)
        print(f"📊 ML Prediction - Score: {score:.3f}")
        
        if score > 0.8:
            print("✅ High anomaly score detected - should trigger blocking!")
        else:
            print(f"⚠️  Anomaly score ({score:.3f}) not high enough for automatic blocking")
    else:
        print(f"❌ Error testing ML prediction: {response.status_code}")
    
    # Test advanced ML prediction
    response = requests.post(f"{API_BASE_URL}/ml-predict-advanced", json=definitive_anomaly_traffic)
    if response.status_code == 200:
        result = response.json()
        advanced_score = result.get('anomaly_score', 0)
        print(f"🔬 Advanced ML - Anomaly Score: {advanced_score:.3f}")
        
        if result.get('anomaly_detected', False):
            print("✅ Advanced ML detected anomaly - should trigger blocking!")
        else:
            print("⚠️  Advanced ML did not detect anomaly")
    else:
        print(f"❌ Error testing advanced ML: {response.status_code}")

def test_multiple_extreme_scenarios():
    """Test multiple extreme scenarios"""
    print("\n🔍 Testing Multiple Extreme Scenarios...")
    
    extreme_scenarios = [
        {
            "name": "DDoS Attack",
            "data": {
                "flow_duration": 0.001,
                "total_fwd_packets": 100000,
                "total_backward_packets": 1,
                "flow_bytes_sec": 10000000,
                "flow_packets_sec": 50000,
                "packet_length_mean": 16,
                "packet_length_std": 0,
                "fwd_packet_length_mean": 16,
                "bwd_packet_length_mean": 16,
                "min_packet_length": 16,
                "max_packet_length": 16,
                "init_win_bytes_forward": 0,
                "init_win_bytes_backward": 0,
                "src_ip": "192.168.1.888",
                "timestamp": datetime.utcnow().isoformat()
            }
        },
        {
            "name": "Port Scan",
            "data": {
                "flow_duration": 0.0001,
                "total_fwd_packets": 1,
                "total_backward_packets": 0,
                "flow_bytes_sec": 1000,
                "flow_packets_sec": 10000,
                "packet_length_mean": 8,
                "packet_length_std": 0,
                "fwd_packet_length_mean": 8,
                "bwd_packet_length_mean": 0,
                "min_packet_length": 8,
                "max_packet_length": 8,
                "init_win_bytes_forward": 0,
                "init_win_bytes_backward": 0,
                "src_ip": "192.168.1.777",
                "timestamp": datetime.utcnow().isoformat()
            }
        }
    ]
    
    for scenario in extreme_scenarios:
        print(f"\n🔍 Testing {scenario['name']} with IP: {scenario['data']['src_ip']}")
        
        response = requests.post(f"{API_BASE_URL}/ml-predict-advanced", json=scenario['data'])
        if response.status_code == 200:
            result = response.json()
            score = result.get('anomaly_score', 0)
            detected = result.get('anomaly_detected', False)
            print(f"📊 {scenario['name']} - Score: {score:.3f}, Detected: {detected}")
            
            if score > 0.8 or detected:
                print(f"✅ {scenario['name']} should trigger blocking!")
            else:
                print(f"⚠️  {scenario['name']} score not high enough")
        else:
            print(f"❌ Error testing {scenario['name']}: {response.status_code}")

def check_final_status():
    """Check the final status after testing"""
    print("\n📋 Final Status Check...")
    
    try:
        # Check ML statistics
        response = requests.get(f"{API_BASE_URL}/ml-stats")
        if response.status_code == 200:
            stats = response.json()
            ml_stats = stats.get('ml_statistics', {})
            blocked_today = ml_stats.get('blocked_today', 0)
            total_ml_alerts = ml_stats.get('total_ml_alerts', 0)
            print(f"🚫 IPs Blocked Today: {blocked_today}")
            print(f"🤖 Total ML Alerts: {total_ml_alerts}")
            
            if blocked_today > 0:
                print("🎉 SUCCESS! IPs have been blocked!")
            else:
                print("⚠️  No IPs blocked yet - checking why...")
                
                # Check if there are any alerts with high scores
                response = requests.get(f"{API_BASE_URL}/ml-stats")
                if response.status_code == 200:
                    stats = response.json()
                    ml_stats = stats.get('ml_statistics', {})
                    avg_score = ml_stats.get('avg_anomaly_score_today', 0)
                    print(f"📊 Average anomaly score today: {avg_score:.3f}")
                    
                    if avg_score < 0.8:
                        print("💡 Average score is below 0.8 threshold - this is why no blocking occurred")
                    else:
                        print("💡 High scores detected but no blocking - check firewall manager logs")
        else:
            print("❌ Could not fetch ML statistics")
            
    except Exception as e:
        print(f"❌ Error checking final status: {e}")

def main():
    """Main testing function"""
    print("🚀 Starting Definitive IP Blocking Testing...")
    print("=" * 60)
    
    # Test definitive blocking
    test_definitive_blocking()
    
    # Test multiple extreme scenarios
    test_multiple_extreme_scenarios()
    
    # Check final status
    check_final_status()
    
    print("\n" + "=" * 60)
    print("✅ Definitive IP Blocking Testing completed!")
    print("\n🎯 Summary:")
    print("1. 🔄 Refresh your Streamlit dashboard to see updates")
    print("2. 🚨 Check 'Real-time Alerts' for new high-severity alerts")
    print("3. 🚫 Look for 'Blocked IPs' counter to increase")
    print("4. 📊 Check 'Overview' page for updated metrics")
    print("\n💡 If blocking still doesn't work:")
    print("- The anomaly scores might not be reaching the 0.8 threshold")
    print("- Check firewall manager logs for any errors")
    print("- Verify the firewall manager is running with sudo privileges")

if __name__ == "__main__":
    main() 