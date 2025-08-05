#!/usr/bin/env python3
"""
IP Blocking Test Script
This script tests the IP blocking functionality with high anomaly scores.
"""

import requests
import json
import time
from datetime import datetime

# Configuration
API_BASE_URL = "http://localhost:5050"

def test_high_anomaly_blocking():
    """Test IP blocking with high anomaly scores"""
    print("🚫 Testing IP Blocking with High Anomaly Scores...")
    
    # Test with very high anomaly score (should trigger blocking)
    high_anomaly_traffic = {
        "flow_duration": 30.0,
        "total_fwd_packets": 5000,
        "total_backward_packets": 1,
        "flow_bytes_sec": 500000,
        "flow_packets_sec": 2000,
        "packet_length_mean": 32,
        "packet_length_std": 1,
        "fwd_packet_length_mean": 32,
        "bwd_packet_length_mean": 32,
        "min_packet_length": 32,
        "max_packet_length": 32,
        "init_win_bytes_forward": 0,
        "init_win_bytes_backward": 0,
        "src_ip": "192.168.1.999",  # Using a test IP that should be blockable
        "timestamp": datetime.utcnow().isoformat()
    }
    
    print(f"🔍 Testing with IP: {high_anomaly_traffic['src_ip']}")
    
    # Test ML prediction
    response = requests.post(f"{API_BASE_URL}/ml-predict", json=high_anomaly_traffic)
    if response.status_code == 200:
        result = response.json()
        print(f"📊 ML Prediction - Score: {result.get('anomaly_score'):.3f}")
        
        # Check if this should trigger blocking (score > 0.8)
        if result.get('anomaly_score', 0) > 0.8:
            print("✅ High anomaly score detected - should trigger blocking")
        else:
            print("⚠️  Anomaly score not high enough for automatic blocking")
    else:
        print(f"❌ Error testing ML prediction: {response.status_code}")
    
    # Test advanced ML prediction
    response = requests.post(f"{API_BASE_URL}/ml-predict-advanced", json=high_anomaly_traffic)
    if response.status_code == 200:
        result = response.json()
        print(f"🔬 Advanced ML - Anomaly Score: {result.get('anomaly_score', 0):.3f}")
        
        if result.get('anomaly_detected', False):
            print("✅ Advanced ML detected anomaly - should trigger blocking")
        else:
            print("⚠️  Advanced ML did not detect anomaly")
    else:
        print(f"❌ Error testing advanced ML: {response.status_code}")

def test_signature_based_blocking():
    """Test signature-based blocking"""
    print("\n🔍 Testing Signature-Based Blocking...")
    
    # Test with high-severity threat
    high_severity_payload = "'; DROP TABLE users; --"
    response = requests.post(f"{API_BASE_URL}/scan", json={
        "payload": high_severity_payload,
        "src_ip": "192.168.1.888",  # Test IP for blocking
        "timestamp": datetime.utcnow().isoformat()
    })
    
    if response.status_code == 200:
        result = response.json()
        if result.get("status") == "threat_detected":
            print(f"✅ High-severity threat detected: {result['details']}")
            print("🚫 This should trigger IP blocking if severity is 'high' or 'critical'")
        else:
            print("❌ High-severity threat not detected")
    else:
        print(f"❌ Error: {response.status_code}")

def check_blocked_ips():
    """Check currently blocked IPs"""
    print("\n📋 Checking Currently Blocked IPs...")
    
    try:
        # Check if there's an endpoint to list blocked IPs
        response = requests.get(f"{API_BASE_URL}/")
        if response.status_code == 200:
            status = response.json()
            print(f"🔧 System Status: {status.get('status')}")
            
            # Check ML statistics for blocked IPs
            response = requests.get(f"{API_BASE_URL}/ml-stats")
            if response.status_code == 200:
                stats = response.json()
                blocked_today = stats.get('ml_statistics', {}).get('blocked_today', 0)
                print(f"🚫 IPs Blocked Today: {blocked_today}")
            else:
                print("❌ Could not fetch ML statistics")
    except Exception as e:
        print(f"❌ Error checking blocked IPs: {e}")

def test_manual_blocking():
    """Test manual IP blocking"""
    print("\n🔧 Testing Manual IP Blocking...")
    
    # This would require sudo privileges, so we'll just show the concept
    print("💡 To manually block an IP, you would need to:")
    print("1. Run: sudo python3 backend/firewall_manager.py block 192.168.1.999 'Test blocking'")
    print("2. Check blocked IPs: sudo python3 backend/firewall_manager.py list")
    print("3. Unblock IP: sudo python3 backend/firewall_manager.py unblock 192.168.1.999")

def main():
    """Main testing function"""
    print("🚀 Starting IP Blocking Testing...")
    print("=" * 50)
    
    # Check current blocked IPs
    check_blocked_ips()
    
    # Test high anomaly blocking
    test_high_anomaly_blocking()
    
    # Test signature-based blocking
    test_signature_based_blocking()
    
    # Show manual blocking instructions
    test_manual_blocking()
    
    print("\n" + "=" * 50)
    print("✅ IP Blocking Testing completed!")
    print("\n📋 Why Blocked IPs might show 0:")
    print("1. 🔒 IP blocking requires sudo privileges (iptables)")
    print("2. 🎯 Anomaly scores must be > 0.8 for automatic blocking")
    print("3. 🚫 Test IPs like 'unknown', 'localhost' are filtered out")
    print("4. 🛡️  Firewall manager needs to be running with proper permissions")
    print("\n💡 To enable IP blocking:")
    print("1. Run firewall manager: sudo python3 backend/firewall_manager.py monitor")
    print("2. Or manually block: sudo python3 backend/firewall_manager.py block <IP> <reason>")

if __name__ == "__main__":
    main() 