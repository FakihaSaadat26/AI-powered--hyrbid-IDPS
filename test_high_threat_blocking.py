#!/usr/bin/env python3
"""
High Threat Blocking Test Script
This script tests IP blocking with extremely high anomaly scores that should trigger blocking.
"""

import requests
import json
import time
from datetime import datetime

# Configuration
API_BASE_URL = "http://localhost:5050"

def test_extreme_anomaly_blocking():
    """Test IP blocking with extreme anomaly scores"""
    print("🚫 Testing Extreme Anomaly Blocking...")
    
    # Test with extreme anomaly score (should definitely trigger blocking)
    extreme_anomaly_traffic = {
        "flow_duration": 100.0,  # Very long duration
        "total_fwd_packets": 10000,  # Massive packet count
        "total_backward_packets": 1,  # Almost no response
        "flow_bytes_sec": 1000000,  # Extremely high bandwidth
        "flow_packets_sec": 5000,  # Very high packet rate
        "packet_length_mean": 16,  # Very small packets
        "packet_length_std": 0,  # No variation
        "fwd_packet_length_mean": 16,
        "bwd_packet_length_mean": 16,
        "min_packet_length": 16,
        "max_packet_length": 16,
        "init_win_bytes_forward": 0,
        "init_win_bytes_backward": 0,
        "src_ip": "192.168.1.666",  # Test IP for blocking
        "timestamp": datetime.utcnow().isoformat()
    }
    
    print(f"🔍 Testing with IP: {extreme_anomaly_traffic['src_ip']}")
    print(f"📊 Traffic characteristics:")
    print(f"   - Duration: {extreme_anomaly_traffic['flow_duration']}s")
    print(f"   - Packets: {extreme_anomaly_traffic['total_fwd_packets']} forward, {extreme_anomaly_traffic['total_backward_packets']} backward")
    print(f"   - Bandwidth: {extreme_anomaly_traffic['flow_bytes_sec']} bytes/sec")
    
    # Test ML prediction
    response = requests.post(f"{API_BASE_URL}/ml-predict", json=extreme_anomaly_traffic)
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
    response = requests.post(f"{API_BASE_URL}/ml-predict-advanced", json=extreme_anomaly_traffic)
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

def test_high_severity_signature():
    """Test high-severity signature-based blocking"""
    print("\n🔍 Testing High-Severity Signature Blocking...")
    
    # Test with multiple high-severity threats
    high_severity_payloads = [
        "'; DROP TABLE users; --",  # SQL Injection
        "<script>alert('XSS')</script>",  # XSS
        "rm -rf /",  # Command injection
        "eval('malicious_code')",  # Code injection
    ]
    
    for i, payload in enumerate(high_severity_payloads):
        test_ip = f"192.168.1.{700 + i}"
        print(f"\n🔍 Testing {payload[:20]}... with IP: {test_ip}")
        
        response = requests.post(f"{API_BASE_URL}/scan", json={
            "payload": payload,
            "src_ip": test_ip,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        if response.status_code == 200:
            result = response.json()
            if result.get("status") == "threat_detected":
                severity = result.get('details', {}).get('severity', 'unknown')
                print(f"✅ Threat detected: {result['details'].get('threat', 'Unknown')} (Severity: {severity})")
                if severity.lower() in ['high', 'critical']:
                    print("🚫 High-severity threat - should trigger IP blocking!")
            else:
                print("❌ Threat not detected")
        else:
            print(f"❌ Error: {response.status_code}")

def check_blocked_ips_status():
    """Check the current status of blocked IPs"""
    print("\n📋 Checking Blocked IPs Status...")
    
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
        else:
            print("❌ Could not fetch ML statistics")
            
        # Check system status
        response = requests.get(f"{API_BASE_URL}/")
        if response.status_code == 200:
            status = response.json()
            services = status.get('services', {})
            print(f"🔧 Services Status:")
            print(f"   - ML Integration: {services.get('ml_integration', 'unknown')}")
            print(f"   - Simple ML: {services.get('simple_ml', 'unknown')}")
            print(f"   - Signature Engine: {services.get('signature_engine', 'unknown')}")
            
    except Exception as e:
        print(f"❌ Error checking status: {e}")

def main():
    """Main testing function"""
    print("🚀 Starting High Threat Blocking Testing...")
    print("=" * 60)
    
    # Check current status
    check_blocked_ips_status()
    
    # Test extreme anomaly blocking
    test_extreme_anomaly_blocking()
    
    # Test high-severity signatures
    test_high_severity_signature()
    
    print("\n" + "=" * 60)
    print("✅ High Threat Blocking Testing completed!")
    print("\n🎯 Next Steps:")
    print("1. 🔄 Refresh your Streamlit dashboard")
    print("2. 🚨 Check 'Real-time Alerts' page for new alerts")
    print("3. 📊 Check 'Overview' page for updated metrics")
    print("4. 🚫 Look for 'Blocked IPs' counter to increase")
    print("\n💡 If blocking still doesn't work:")
    print("- Check firewall manager logs for errors")
    print("- Verify anomaly scores are > 0.8")
    print("- Ensure firewall manager is running with sudo")

if __name__ == "__main__":
    main() 