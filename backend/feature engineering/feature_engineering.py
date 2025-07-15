import pandas   as pd
from supabase_client import supabase

# fetching data from supabase
def fetch_raw_data():
    response = supabase.table("network_data").select("*").limit(1000).execute()
    data = pd.DataFrame(response.data)
    return data