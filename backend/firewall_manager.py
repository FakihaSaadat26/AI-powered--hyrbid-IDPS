import subprocess
import json
import time
import logging
import requests
from datetime import datetime, timedelta
import threading
import os

# Configuration
API_BASE_URL = "http://localhost:5000"
RULE_ENGINE_ENDPOINT = f"{API_BASE_URL}/run-rule-engine"
BLOCKED_IPS_FILE = "blocked_ips.json"
CHECK_INTERVAL = 30  # Check for new threats every 30 seconds
BLOCK_DURATION = 3600  # Block IPs for 1 hour (in seconds)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('firewall_manager.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class FirewallManager:
    def __init__(self):
        self.blocked_ips = self.load_blocked_ips()
        self.create_custom_chain()
    
    def load_blocked_ips(self):
        """Load previously blocked IPs from file"""
        try:
            if os.path.exists(BLOCKED_IPS_FILE):
                with open(BLOCKED_IPS_FILE, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            logger.error(f"Error loading blocked IPs: {e}")
            return {}
    
    def save_blocked_ips(self):
        """Save blocked IPs to file"""
        try:
            with open(BLOCKED_IPS_FILE, 'w') as f:
                json.dump(self.blocked_ips, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving blocked IPs: {e}")
    
    def create_custom_chain(self):
        """Create custom iptables chain for our blocks"""
        try:
            # Create custom chain
            subprocess.run([
                "sudo", "iptables", "-t", "filter", "-N", "IDPS_BLOCK"
            ], capture_output=True)
            logger.info("Created IDPS_BLOCK chain")
        except:
            pass  # Chain might already exist
        
        # Ensure our chain is referenced in INPUT
        try:
            subprocess.run([
                "sudo", "iptables", "-I", "INPUT", "-j", "IDPS_BLOCK"
            ], capture_output=True)
            logger.info("Added IDPS_BLOCK to INPUT chain")
        except Exception as e:
            logger.warning(f"Chain reference might already exist: {e}")
    
    def block_ip(self, ip_address, reason="Threat detected"):
        """Block an IP address using iptables"""
        if ip_address in ["unknown", "localhost", "127.0.0.1", ""]:
            logger.warning(f"Skipping block for invalid IP: {ip_address}")
            return False
        
        try:
            # Add iptables rule
            result = subprocess.run([
                "sudo", "iptables", "-I", "IDPS_BLOCK", "-s", ip_address, "-j", "DROP"
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                # Record the block
                self.blocked_ips[ip_address] = {
                    "blocked_at": datetime.now().isoformat(),
                    "reason": reason,
                    "expires_at": (datetime.now() + timedelta(seconds=BLOCK_DURATION)).isoformat()
                }
                self.save_blocked_ips()
                
                logger.warning(f"🚫 BLOCKED IP: {ip_address} - Reason: {reason}")
                return True
            else:
                logger.error(f"Failed to block {ip_address}: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error blocking IP {ip_address}: {e}")
            return False
    
    def unblock_ip(self, ip_address):
        """Unblock an IP address"""
        try:
            # Remove iptables rule
            result = subprocess.run([
                "sudo", "iptables", "-D", "IDPS_BLOCK", "-s", ip_address, "-j", "DROP"
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                # Remove from our records
                if ip_address in self.blocked_ips:
                    del self.blocked_ips[ip_address]
                    self.save_blocked_ips()
                
                logger.info(f"✅ UNBLOCKED IP: {ip_address}")
                return True
            else:
                logger.warning(f"Failed to unblock {ip_address}: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error unblocking IP {ip_address}: {e}")
            return False
    
    def cleanup_expired_blocks(self):
        """Remove expired IP blocks"""
        current_time = datetime.now()
        expired_ips = []
        
        for ip, block_info in self.blocked_ips.items():
            expires_at = datetime.fromisoformat(block_info['expires_at'])
            if current_time > expires_at:
                expired_ips.append(ip)
        
        for ip in expired_ips:
            logger.info(f"⏰ Block expired for IP: {ip}")
            self.unblock_ip(ip)
    
    def check_for_threats(self):
        """Check API for new threats and block IPs"""
        try:
            response = requests.get(RULE_ENGINE_ENDPOINT, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                alerts = result.get('alerts', [])
                
                logger.info(f"📊 Rule engine check: {len(alerts)} new alerts")
                
                for alert in alerts:
                    src_ip = alert.get('src_ip', 'unknown')
                    threat_type = alert.get('threat_type', 'Unknown threat')
                    severity = alert.get('severity', 'Medium')
                    
                    # Block high severity threats immediately
                    if severity.lower() in ['high', 'critical'] and src_ip not in self.blocked_ips:
                        if self.block_ip(src_ip, f"{threat_type} ({severity})"):
                            # Update alert in database to show action taken
                            self.update_alert_action(alert, "IP_BLOCKED")
                
            else:
                logger.error(f"Rule engine API error: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error checking for threats: {e}")
    
    def update_alert_action(self, alert, action):
        """Update alert in database to show action taken (optional enhancement)"""
        # This would require an additional API endpoint to update alerts
        # For now, we'll just log it
        logger.info(f"Action taken for alert: {action}")
    
    def list_blocked_ips(self):
        """List currently blocked IPs"""
        if not self.blocked_ips:
            print("No IPs currently blocked.")
            return
        
        print("\n🚫 Currently Blocked IPs:")
        print("=" * 60)
        for ip, info in self.blocked_ips.items():
            blocked_at = datetime.fromisoformat(info['blocked_at'])
            expires_at = datetime.fromisoformat(info['expires_at'])
            print(f"IP: {ip}")
            print(f"  Reason: {info['reason']}")
            print(f"  Blocked: {blocked_at.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"  Expires: {expires_at.strftime('%Y-%m-%d %H:%M:%S')}")
            print("-" * 40)
    
    def manual_block(self, ip_address, reason="Manual block"):
        """Manually block an IP"""
        return self.block_ip(ip_address, reason)
    
    def manual_unblock(self, ip_address):
        """Manually unblock an IP"""
        return self.unblock_ip(ip_address)
    
    def start_monitoring(self):
        """Start continuous monitoring for threats"""
        logger.info("🔍 Starting firewall threat monitoring...")
        
        while True:
            try:
                # Check for expired blocks
                self.cleanup_expired_blocks()
                
                # Check for new threats
                self.check_for_threats()
                
                # Sleep before next check
                time.sleep(CHECK_INTERVAL)
                
            except KeyboardInterrupt:
                logger.info("🛑 Monitoring stopped by user")
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(CHECK_INTERVAL)

def print_usage():
    """Print usage instructions"""
    print("""
🔥 Firewall Manager - Week 2 Task
================================

Usage: python firewall_manager.py [command] [args]

Commands:
  monitor              - Start continuous threat monitoring (default)
  block <ip> <reason>  - Manually block an IP
  unblock <ip>         - Manually unblock an IP
  list                 - List currently blocked IPs
  cleanup              - Remove expired blocks

Examples:
  sudo python firewall_manager.py monitor
  sudo python firewall_manager.py block 192.168.1.100 "Suspicious activity"
  sudo python firewall_manager.py unblock 192.168.1.100
  sudo python firewall_manager.py list

Note: This script requires sudo privileges to manage iptables rules.
    """)

if __name__ == "__main__":
    import sys
    
    # Check if running with sudo
    if os.geteuid() != 0:
        print("❌ This script requires sudo privileges to manage iptables rules.")
        print("Please run with: sudo python firewall_manager.py")
        sys.exit(1)
    
    fw_manager = FirewallManager()
    
    if len(sys.argv) < 2:
        # Default action: start monitoring
        fw_manager.start_monitoring()
    else:
        command = sys.argv[1].lower()
        
        if command == "monitor":
            fw_manager.start_monitoring()
        elif command == "block" and len(sys.argv) >= 3:
            ip = sys.argv[2]
            reason = " ".join(sys.argv[3:]) if len(sys.argv) > 3 else "Manual block"
            fw_manager.manual_block(ip, reason)
        elif command == "unblock" and len(sys.argv) >= 3:
            ip = sys.argv[2]
            fw_manager.manual_unblock(ip)
        elif command == "list":
            fw_manager.list_blocked_ips()
        elif command == "cleanup":
            fw_manager.cleanup_expired_blocks()
        else:
            print_usage()