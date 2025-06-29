import re
from backend.supabase_client import supabase

def get_signature_rules():
    response = supabase.table("signature_rules").select("*").execute()
    return response.data

def check_payload_against_signatures(payload):
    rules = get_signature_rules()
    for rule in rules:
        pattern = rule['regex_pattern']
        if re.search(pattern.encode(), payload.encode()):
            return {
                "threat": rule["name"],
                "severity": rule["severity"],
                "matched_pattern": pattern
            }
    return None
