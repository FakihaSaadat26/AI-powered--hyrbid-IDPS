from flask import Flask, request, jsonify
from signature_engine import check_payload_against_signatures
from supabase_client import supabase

app = Flask(__name__)

@app.route("/scan", methods=["POST"])
def scan_endpoint():  # Renamed to avoid confusion with the scan() function in signature_engine.py
    data = request.get_json()

    # Safety check
    if not data:
        return jsonify({"error": "No JSON data received"}), 400

    payload = data.get("payload", "")
    src_ip = data.get("src_ip", "unknown")

    # Run signature match 
    result = check_payload_against_signatures(payload)

    if result:
        # Log to Supabase alert table
        supabase.table("alerts").insert({
            "src_ip": src_ip,
            "threat_type": result["threat"],
            "severity": result["severity"],
            "action_taken": "None",
            "detected_by": "signature"
        }).execute()

        return jsonify({
            "status": "threat_detected",
            "details": result
        }), 200

    else:
        return jsonify({"status": "clean"}), 200

if __name__ == "__main__":
    app.run(debug=True)
