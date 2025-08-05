#!/usr/bin/env python3
"""
Threat Detection Testing Script
This script simulates various types of threats to test the IDPS system.
"""

import requests
import json
import time
from datetime import datetime
import random

# Configuration
API_BASE_URL = "http://localhost:5050"

def test_signature_based_detection():
    """Test signature-based threat detection"""
    print("🔍 Testing Signature-Based Detection...")
    
    # Test 1: SQL Injection
    sql_injection_payload = "'; DROP TABLE users; --"
    response = requests.post(f"{API_BASE_URL}/scan", json={
        "payload": sql_injection_payload,
        "src_ip": "192.168.1.100",
        "timestamp": datetime.utcnow().isoformat()
    })
    
    if response.status_code == 200:
        result = response.json()
        if result.get("status") == "threat_detected":
            print(f"✅ SQL Injection detected: {result['details']}")
        else:
            print("❌ SQL Injection not detected")
    else:
        print(f"❌ Error: {response.status_code}")
    
    # Test 2: XSS Attack
    xss_payload = "<script>alert('XSS')</script>"
    response = requests.post(f"{API_BASE_URL}/scan", json={
        "payload": xss_payload,
        "src_ip": "192.168.1.101",
        "timestamp": datetime.utcnow().isoformat()
    })
    
    if response.status_code == 200:
        result = response.json()
        if result.get("status") == "threat_detected":
            print(f"✅ XSS Attack detected: {result['details']}")
        else:
            print("❌ XSS Attack not detected")
    else:
        print(f"❌ Error: {response.status_code}")

def test_ml_detection():
    """Test ML-based anomaly detection"""
    print("\n🤖 Testing ML-Based Detection...")
    
    # Test 1: Normal traffic
    normal_traffic = {
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
        "src_ip": "192.168.1.200",
        "timestamp": datetime.utcnow().isoformat()
    }
    
    response = requests.post(f"{API_BASE_URL}/ml-predict", json=normal_traffic)
    if response.status_code == 200:
        result = response.json()
        print(f"📊 Normal Traffic - Prediction: {result.get('prediction')}, Score: {result.get('anomaly_score'):.3f}")
    else:
        print(f"❌ Error testing normal traffic: {response.status_code}")
    
    # Test 2: DDoS Attack traffic
    ddos_traffic = {
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
        "src_ip": "192.168.1.201",
        "timestamp": datetime.utcnow().isoformat()
    }
    
    response = requests.post(f"{API_BASE_URL}/ml-predict", json=ddos_traffic)
    if response.status_code == 200:
        result = response.json()
        print(f"🚨 DDoS Traffic - Prediction: {result.get('prediction')}, Score: {result.get('anomaly_score'):.3f}")
    else:
        print(f"❌ Error testing DDoS traffic: {response.status_code}")
    
    # Test 3: Port Scan traffic
    port_scan_traffic = {
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
        "src_ip": "192.168.1.202",
        "timestamp": datetime.utcnow().isoformat()
    }
    
    response = requests.post(f"{API_BASE_URL}/ml-predict", json=port_scan_traffic)
    if response.status_code == 200:
        result = response.json()
        print(f"🔍 Port Scan Traffic - Prediction: {result.get('prediction')}, Score: {result.get('anomaly_score'):.3f}")
    else:
        print(f"❌ Error testing port scan traffic: {response.status_code}")

def test_advanced_ml_detection():
    """Test advanced ML detection"""
    print("\n🔬 Testing Advanced ML Detection...")
    
    # Test with advanced ML endpoint
    test_data = {
        "flow_duration": 10.0,
        "total_fwd_packets": 500,
        "total_backward_packets": 10,
        "flow_bytes_sec": 50000,
        "flow_packets_sec": 400,
        "packet_length_mean": 128,
        "packet_length_std": 50,
        "fwd_packet_length_mean": 128,
        "bwd_packet_length_mean": 128,
        "min_packet_length": 64,
        "max_packet_length": 512,
        "init_win_bytes_forward": 0,
        "init_win_bytes_backward": 0,
        "src_ip": "192.168.1.203",
        "timestamp": datetime.utcnow().isoformat()
    }
    
    response = requests.post(f"{API_BASE_URL}/ml-predict-advanced", json=test_data)
    if response.status_code == 200:
        result = response.json()
        print(f"🔬 Advanced ML - Result: {result}")
    else:
        print(f"❌ Error testing advanced ML: {response.status_code}")

def test_rule_engine():
    """Test rule-based detection"""
    print("\n⚙️ Testing Rule Engine...")
    
    response = requests.get(f"{API_BASE_URL}/run-rule-engine")
    if response.status_code == 200:
        result = response.json()
        print(f"⚙️ Rule Engine - Alerts generated: {result.get('total_alerts_generated', 0)}")
        if result.get('alerts'):
            print(f"📋 Alert details: {result['alerts'][:2]}...")  # Show first 2 alerts
    else:
        print(f"❌ Error testing rule engine: {response.status_code}")

def check_system_status():
    """Check system status"""
    print("\n📊 Checking System Status...")
    
    response = requests.get(f"{API_BASE_URL}/")
    if response.status_code == 200:
        status = response.json()
        print(f"✅ System Status: {status.get('status')}")
        print(f"🔧 Services: {status.get('services')}")
        print(f"🤖 ML Details: {status.get('ml_details')}")
    else:
        print(f"❌ Error checking status: {response.status_code}")

def main():
    """Main testing function"""
    print("🚀 Starting Threat Detection Testing...")
    print("=" * 50)
    
    # Check system status first
    check_system_status()
    
    # Run all tests
    test_signature_based_detection()
    test_ml_detection()
    test_advanced_ml_detection()
    test_rule_engine()
    
    print("\n" + "=" * 50)
    print("✅ Testing completed!")
    print("\n📋 What to check in the frontend:")
    print("1. 🚨 Real-time Alerts page - Look for new alerts")
    print("2. 📊 Overview page - Check if metrics updated")
    print("3. 🤖 ML Detection page - View prediction results")
    print("4. 🔍 Threat Analysis page - Analyze threat patterns")
    print("\n🔄 Refresh the dashboard to see real-time updates!")

if __name__ == "__main__":
    main() 