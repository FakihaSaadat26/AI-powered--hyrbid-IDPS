from supabase_client import supabase
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_ml_alerts_table():
    """Create ml_alerts table structure"""
    
    sql_create_table = """
    CREATE TABLE IF NOT EXISTS ml_alerts (
        id SERIAL PRIMARY KEY,
        src_ip VARCHAR(45) NOT NULL,
        dst_ip VARCHAR(45),
        dst_port INTEGER,
        anomaly_score DECIMAL(5,4) NOT NULL,
        isolation_forest_score DECIMAL(10,6),
        ocsvm_score DECIMAL(10,6),
        model_prediction VARCHAR(20) NOT NULL DEFAULT 'ANOMALY',
        threshold_used DECIMAL(3,2) NOT NULL DEFAULT 0.70,
        action_taken VARCHAR(50) DEFAULT 'PENDING',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );
    
    -- Create indexes for better performance
    CREATE INDEX IF NOT EXISTS idx_ml_alerts_src_ip ON ml_alerts(src_ip);
    CREATE INDEX IF NOT EXISTS idx_ml_alerts_created_at ON ml_alerts(created_at);
    CREATE INDEX IF NOT EXISTS idx_ml_alerts_anomaly_score ON ml_alerts(anomaly_score);
    CREATE INDEX IF NOT EXISTS idx_ml_alerts_action_taken ON ml_alerts(action_taken);
    
    -- Create RLS policies (Row Level Security)
    ALTER TABLE ml_alerts ENABLE ROW LEVEL SECURITY;
    
    CREATE POLICY "ml_alerts_select_policy" ON ml_alerts FOR SELECT USING (true);
    CREATE POLICY "ml_alerts_insert_policy" ON ml_alerts FOR INSERT WITH CHECK (true);
    CREATE POLICY "ml_alerts_update_policy" ON ml_alerts FOR UPDATE USING (true);
    """
    
    print("🗃️ ML Alerts Table Setup")
    print("=" * 50)
    print("Please execute the following SQL in your Supabase SQL editor:")
    print()
    print(sql_create_table)
    print()
    print("After creating the table, this script will test the connection...")
    input("Press Enter after you've created the table in Supabase...")
    
    # Test the table
    test_ml_alerts_table()

def test_ml_alerts_table():
    """Test if ml_alerts table exists and is accessible"""
    try:
        # Try to read from the table
        response = supabase.table("ml_alerts").select("*").limit(1).execute()
        logger.info("✅ ml_alerts table is accessible")
        
        # Test insert (then delete)
        test_record = {
            "src_ip": "127.0.0.1",
            "anomaly_score": 0.95,
            "model_prediction": "TEST",
            "action_taken": "TEST_INSERT"
        }
        
        insert_response = supabase.table("ml_alerts").insert([test_record]).execute()
        if insert_response.data:
            record_id = insert_response.data[0]['id']
            logger.info("✅ Insert test successful")
            
            # Clean up test record
            supabase.table("ml_alerts").delete().eq("id", record_id).execute()
            logger.info("✅ Test record cleaned up")
        
        print("\n🎉 Database setup completed successfully!")
        print("You can now run the ML integration script.")
        
    except Exception as e:
        logger.error(f"❌ Error accessing ml_alerts table: {e}")
        print("\n❌ Table setup incomplete. Please check your Supabase configuration.")

def check_existing_tables():
    """Check what tables already exist"""
    print("\n📋 Checking existing tables...")
    
    tables_to_check = ["network_data", "alerts", "signature_rules", "ml_alerts"]
    
    for table in tables_to_check:
        try:
            response = supabase.table(table).select("*").limit(1).execute()
            print(f"✅ {table}: exists and accessible")
        except Exception as e:
            print(f"❌ {table}: {str(e)}")

if __name__ == "__main__":
    print("🚀 Database Setup for ML Integration")
    print("=" * 50)
    
    # Check existing tables first
    check_existing_tables()
    
    print("\n" + "=" * 50)
    
    # Create ml_alerts table
    create_ml_alerts_table()