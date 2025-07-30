from scapy.all import sniff, IP, TCP, UDP, Raw
import requests
import json
import time
from datetime import datetime
import threading
import queue
import logging

# Configuration
API_BASE_URL = "http://localhost:5000"
SCAN_ENDPOINT = f"{API_BASE_URL}/scan"
INTERFACE = None  # None = all interfaces, or specify like "eth0"
PACKET_QUEUE = queue.Queue()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('packet_sniffer.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def extract_packet_data(packet):
    """Extract relevant data from captured packet"""
    try:
        if not packet.haslayer(IP):
            return None
            
        ip_layer = packet[IP]
        data = {
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "protocol": ip_layer.proto,
            "timestamp": datetime.now().isoformat() + 'Z'
        }
        
        # Extract TCP/UDP info
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            data.update({
                "src_port": tcp_layer.sport,
                "dst_port": tcp_layer.dport,
                "tcp_flags": tcp_layer.flags,
                "protocol_name": "TCP"
            })
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            data.update({
                "src_port": udp_layer.sport,
                "dst_port": udp_layer.dport,
                "protocol_name": "UDP"
            })
        
        # Extract payload for signature detection
        payload = ""
        if packet.haslayer(Raw):
            raw_layer = packet[Raw]
            try:
                payload = str(raw_layer.load.decode('utf-8', errors='ignore'))
            except:
                payload = str(raw_layer.load)
        
        data["payload"] = payload
        data["packet_size"] = len(packet)
        
        return data
        
    except Exception as e:
        logger.error(f"Error extracting packet data: {e}")
        return None

def send_to_api(packet_data):
    """Send packet data to Flask API for analysis"""
    try:
        # Prepare data for signature detection
        api_data = {
            "payload": packet_data.get("payload", ""),
            "src_ip": packet_data.get("src_ip", "unknown"),
            "timestamp": packet_data.get("timestamp")
        }
        
        response = requests.post(
            SCAN_ENDPOINT,
            json=api_data,
            headers={"Content-Type": "application/json"},
            timeout=5
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get("status") == "threat_detected":
                logger.warning(f"🚨 THREAT DETECTED from {packet_data['src_ip']}: {result['details']}")
            else:
                logger.info(f"✅ Clean packet from {packet_data['src_ip']}")
        else:
            logger.error(f"API error: {response.status_code} - {response.text}")
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to send packet to API: {e}")
    except Exception as e:
        logger.error(f"Unexpected error in send_to_api: {e}")

def packet_handler(packet):
    """Handle each captured packet"""
    packet_data = extract_packet_data(packet)
    if packet_data:
        # Add to queue for processing
        PACKET_QUEUE.put(packet_data)

def api_worker():
    """Worker thread to process packet queue and send to API"""
    while True:
        try:
            # Get packet from queue with timeout
            packet_data = PACKET_QUEUE.get(timeout=1)
            
            # Only send packets with payload for signature detection
            if packet_data.get("payload") and len(packet_data["payload"].strip()) > 0:
                send_to_api(packet_data)
            
            PACKET_QUEUE.task_done()
            
        except queue.Empty:
            continue
        except Exception as e:
            logger.error(f"Error in API worker: {e}")

def start_packet_capture():
    """Start packet capture with filtering"""
    logger.info("🎯 Starting packet sniffer...")
    logger.info(f"📡 Monitoring interface: {INTERFACE or 'all interfaces'}")
    logger.info(f"🔗 API endpoint: {SCAN_ENDPOINT}")
    
    # Start API worker thread
    api_thread = threading.Thread(target=api_worker, daemon=True)
    api_thread.start()
    logger.info("🔧 API worker thread started")
    
    try:
        # Filter for HTTP, FTP, Telnet, SSH traffic (common attack vectors)
        # You can modify this filter based on your needs
        packet_filter = "tcp port 80 or tcp port 8080 or tcp port 21 or tcp port 23 or tcp port 22 or tcp port 443"
        
        logger.info(f"🔍 Applying filter: {packet_filter}")
        
        # Start sniffing
        sniff(
            iface=INTERFACE,
            filter=packet_filter,
            prn=packet_handler,
            store=0  # Don't store packets in memory
        )
        
    except KeyboardInterrupt:
        logger.info("🛑 Packet capture stopped by user")
    except Exception as e:
        logger.error(f"❌ Error in packet capture: {e}")

def test_api_connection():
    """Test connection to Flask API"""
    try:
        response = requests.get(f"{API_BASE_URL}/", timeout=5)
        logger.info("✅ API connection successful")
        return True
    except:
        logger.error("❌ Cannot connect to Flask API. Make sure it's running on localhost:5000")
        return False

if __name__ == "__main__":
    print("🚀 Packet Sniffer - Week 1 Task")
    print("=" * 50)
    
    # Test API connection first
    if not test_api_connection():
        print("Please start the Flask API first: python app.py")
        exit(1)
    
    print("📋 Configuration:")
    print(f"   Interface: {INTERFACE or 'All interfaces'}")
    print(f"   API URL: {SCAN_ENDPOINT}")
    print("\n🎯 Starting packet capture... (Press Ctrl+C to stop)")
    print("📝 Logs will be written to 'packet_sniffer.log'")
    print("-" * 50)
    
    start_packet_capture()