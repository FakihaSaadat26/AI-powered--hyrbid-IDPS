# app.py
from flask import Flask, request, jsonify
from signature.signature_engine import check_payload_against_signatures
from rules.flow_rule_engine import detect_ddos_bursts, detect_failed_login_bursts, detect_syn_flood_flows


from supabase_client import supabase
from utils.logger import logger

app = Flask(__name__)

# --- Signature-based detection endpoint ---
@app.route("/scan", methods=["POST"])
def scan_endpoint():
    data = request.get_json()

    if not data:
        logger.warning("Received request with no JSON data.")
        return jsonify({"error": "No JSON data received"}), 400

    payload = data.get("payload", "")
    src_ip = data.get("src_ip", "unknown")
    
    logger.info(f"Received scan request from IP: {src_ip}")

    result = check_payload_against_signatures(payload)

    if result:
        logger.warning(f"Threat detected from IP {src_ip}: {result['threat']} (Severity: {result['severity']})")

        supabase.table("alerts").insert({
            "src_ip": src_ip,
            "threat_type": result["threat"],
            "severity": result["severity"],
            "action_taken": "None",
            "detected_by": "signature",
            
            "timestamp": request.headers.get("timestamp", None) 
        }).execute()
       
   

        logger.info("Threat info saved to Supabase.")

        return jsonify({
            "status": "threat_detected",
            "details": result
        }), 200
    else:
        logger.info(f"No threat detected from IP {src_ip}. Payload clean.")
        return jsonify({"status": "clean"}), 200


# --- Rule-based detection endpoint ---
@app.route("/run-rule-engine", methods=["GET"])
def run_rule_engine():
    syn_alerts = detect_syn_flood_flows()
    login_alerts = detect_failed_login_bursts()
    ddos_alerts = detect_ddos_bursts()

    total_alerts = syn_alerts + login_alerts + ddos_alerts

    return jsonify({
        "status": "Rule engine detection completed",
        "total_alerts_generated": len(total_alerts),
        "alerts": total_alerts
    }), 200


if __name__ == "__main__":
    app.run(debug=True)
