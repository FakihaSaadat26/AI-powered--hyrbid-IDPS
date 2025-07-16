import time
from utils.logger import logger
from supabase_client import supabase
#pagination to load all attacks
def fetch_all_ddos_rows():
    chunk_size = 1000
    offset = 0
    all_rows = []

    while True:
        response = supabase.table("network_data") \
            .select("*") \
            .eq("label", "2") \
            .range(offset, offset + chunk_size - 1) \
            .execute()

        rows = response.data
        all_rows.extend(rows)

        print(f"Fetched {len(rows)} rows from offset {offset}")

        if len(rows) < chunk_size:
            break  

        offset += chunk_size

    return all_rows


# --- DDoS BURST Detection based on label ---
def detect_ddos_bursts():
    print("Running DDoS burst detection...")
    ddos_rows = fetch_all_ddos_rows()
    print(f"DDoS rows fetched: {len(ddos_rows)}")

    alerts = []
    if len(ddos_rows) > 100:
        alert_msg = f"[DDoS BURST] Total rows: {len(ddos_rows)} labeled as DDoS"
        logger.warning(alert_msg)
        alerts.append({
            "src_ip": "unknown",
            "threat_type": "DDoS Burst Detected",
            "severity": "High",
            "action_taken": "None",
            "detected_by": "rule_engine",
            "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ')
        })

        supabase.table("alerts").insert(alerts).execute()

    return alerts
# --- SYN FLOOD Detection (using high packets/sec + short duration) ---
def detect_syn_flood_flows():
    print("Running SYN flood detection...")
    try:
        response = supabase.table("network_data") \
            .select("flow_packets_sec", "flow_duration") \
            .gt("flow_packets_sec", 1000) \
            .lt("flow_duration", 1000) \
            .execute()

        alerts = []
        for row in response.data:
            alert_msg = f"[SYN FLOOD] Packets/sec: {row['flow_packets_sec']} | Duration: {row['flow_duration']}"
            logger.warning(alert_msg)
            alerts.append({
                "src_ip": "unknown",
                "threat_type": "SYN Flood Detected",
                "severity": "Medium",
                "action_taken": "None",
                "detected_by": "rule",
                "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ')
            })

        if alerts:
            supabase.table("alerts").insert(alerts).execute()
        return alerts
    except Exception as e:
        logger.error(f"Error in detect_syn_flood_flows: {e}")
        return []

# --- Failed Login Burst Detection on ports like 22 (SSH), 21 (FTP), etc. ---
def detect_failed_login_bursts():
    print("Running failed login burst detection...")
    try:
        response = supabase.table("network_data") \
            .select("dst_port", "packet_length_mean", "flow_duration") \
            .lt("packet_length_mean", 100) \
            .lt("flow_duration", 1000) \
            .in_("dst_port", [22, 21, 23, 3306]) \
            .execute()

        port_counter = {}
        for row in response.data:
            port = row["dst_port"]
            port_counter[port] = port_counter.get(port, 0) + 1

        alerts = []
        for port, count in port_counter.items():
            if count >= 5:
                alert_msg = f"[FAILED LOGIN BURST] Port {port} | Attempts: {count}"
                logger.warning(alert_msg)
                alerts.append({
                    "src_ip": "unknown",
                    "threat_type": f"Failed Login Burst on port {port}",
                    "severity": "Medium",
                    "action_taken": "None",
                    "detected_by": "rule",
                    "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ')
                })

        if alerts:
            supabase.table("alerts").insert(alerts).execute()
        return alerts
    except Exception as e:
        logger.error(f"Error in detect_failed_login_bursts: {e}")
        return []
