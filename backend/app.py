from flask import Flask, request, jsonify
from backend.signature_engine import check_payload_against_signatures
from backend.supabase_client import supabase

app = Flask(__name__)

@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    payload = data.get("payload", "")
    src_ip = data.get("src_ip", "unknown")

    result = check_payload_against_signatures(payload)

    if result:
        # Log to Supabase alerts
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
