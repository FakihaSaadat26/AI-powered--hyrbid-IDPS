import re
from supabase_client import supabase  

def get_signature_rules():
  
#   print("📡 Fetching rules from Supabase...")
    response = supabase.table("signature_rules").select("*").execute()
    # print(" Raw response from Supabase:", response.data)
    return response.data

def check_payload_against_signatures(payload):
    # print(" Signature detection function called.")
    rules = get_signature_rules()
    for rule in rules:
        pattern = rule['regex_pattern']
        # print("printing rules: ")
        # print(rule)
     
        # print(f" Testing pattern: {pattern} on payload: {payload}")
        if re.search(pattern, payload):
            print("Match found!")
            return {
                "threat": rule["name"],
                "severity": rule["severity"],
                "matched_pattern": pattern
            }
    # print(" No match.")
    return None
