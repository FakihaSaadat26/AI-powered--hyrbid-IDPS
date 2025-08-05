import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json
import time
from supabase_client import supabase

# Page configuration
st.set_page_config(
    page_title="AI-Powered Hybrid IDPS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #1e3c72 0%, #2a5298 100%);
        padding: 1rem;
        border-radius: 10px;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: white;
        padding: 1rem;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        border-left: 4px solid #2a5298;
    }
    .alert-high { border-left-color: #dc3545; }
    .alert-medium { border-left-color: #ffc107; }
    .alert-low { border-left-color: #28a745; }
    
    .stDataFrame {
        border: 1px solid #ddd;
        border-radius: 5px;
    }
</style>
""", unsafe_allow_html=True)

# Configuration
API_BASE_URL = "http://localhost:5050"

# Helper function to safely parse datetime columns
def safe_datetime_parse(df, column_name):
    """
    Safely parse datetime columns with various formats
    """
    if df.empty or column_name not in df.columns:
        return df
    
    try:
        # First try: ISO8601 format (most common for your data)
        df[column_name] = pd.to_datetime(df[column_name], format='ISO8601')
    except (ValueError, TypeError):
        try:
            # Second try: UTC timezone handling
            df[column_name] = pd.to_datetime(df[column_name], utc=True)
        except (ValueError, TypeError):
            try:
                # Third try: Mixed format inference
                df[column_name] = pd.to_datetime(df[column_name], format='mixed')
            except (ValueError, TypeError):
                try:
                    # Fourth try: Standard pandas inference
                    df[column_name] = pd.to_datetime(df[column_name], infer_datetime_format=True)
                except Exception as e:
                    st.warning(f"Could not parse {column_name} timestamps: {e}")
                    # If all else fails, leave the column as is
    
    return df

class IDPSDashboard:
    def __init__(self):
        self.api_base = API_BASE_URL
        
    def check_api_health(self):
        """Check if the Flask API is running"""
        try:
            response = requests.get(f"{self.api_base}/", timeout=5)
            return response.status_code == 200, response.json()
        except Exception as e:
            return False, str(e)
    
    def get_alerts_data(self, limit=100):
        """Fetch alerts from Supabase"""
        try:
            response = supabase.table("alerts").select("*").order("id", desc=True).limit(limit).execute()
            df = pd.DataFrame(response.data) if response.data else pd.DataFrame()
            # Parse datetime columns immediately after fetching
            df = safe_datetime_parse(df, 'timestamp')
            return df
        except Exception as e:
            st.error(f"Error fetching alerts: {e}")
            return pd.DataFrame()
    
    def get_ml_alerts_data(self, limit=100):
        """Fetch ML alerts from Supabase"""
        try:
            response = supabase.table("ml_alerts").select("*").order("id", desc=True).limit(limit).execute()
            df = pd.DataFrame(response.data) if response.data else pd.DataFrame()
            # Parse datetime columns immediately after fetching
            df = safe_datetime_parse(df, 'created_at')
            return df
        except Exception as e:
            st.error(f"Error fetching ML alerts: {e}")
            return pd.DataFrame()
    
    def get_network_data(self, limit=50):
        """Fetch network data from Supabase"""
        try:
            response = supabase.table("network_data").select("*").order("id", desc=True).limit(limit).execute()
            df = pd.DataFrame(response.data) if response.data else pd.DataFrame()
            # Parse datetime columns if they exist
            if 'timestamp' in df.columns:
                df = safe_datetime_parse(df, 'timestamp')
            if 'created_at' in df.columns:
                df = safe_datetime_parse(df, 'created_at')
            return df
        except Exception as e:
            st.error(f"Error fetching network data: {e}")
            return pd.DataFrame()

def main():
    dashboard = IDPSDashboard()
    
    # Header
    st.markdown("""
    <div class="main-header">
        <h1 style="color: white; margin: 0;">🛡️ AI-Powered Hybrid IDPS Dashboard</h1>
        <p style="color: #b8d4f0; margin: 0; margin-top: 0.5rem;">Real-time Network Intrusion Detection & Prevention System</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar
    st.sidebar.title("🎛️ Control Panel")
    
    # API Health Check
    is_healthy, health_data = dashboard.check_api_health()
    if is_healthy:
        st.sidebar.success("✅ API Connected")
        with st.sidebar.expander("🔍 API Details"):
            st.json(health_data)
    else:
        st.sidebar.error("❌ API Disconnected")
        st.sidebar.write(f"Error: {health_data}")
    
    # Navigation
    page = st.sidebar.selectbox(
        "📋 Select Dashboard",
        ["🏠 Overview", "🚨 Real-time Alerts", "🤖 ML Detection", "🔍 Threat Analysis", "⚙️ System Controls", "📊 Reports"]
    )
    
    # Auto-refresh
    auto_refresh = st.sidebar.checkbox("🔄 Auto Refresh (30s)", value=False)
    if auto_refresh:
        time.sleep(30)
        st.rerun()
    
    # Manual refresh button
    if st.sidebar.button("🔄 Refresh Now"):
        st.rerun()
    
    # Page routing
    if page == "🏠 Overview":
        show_overview_page(dashboard)
    elif page == "🚨 Real-time Alerts":
        show_alerts_page(dashboard)
    elif page == "🤖 ML Detection":
        show_ml_detection_page(dashboard)
    elif page == "🔍 Threat Analysis":
        show_threat_analysis_page(dashboard)
    elif page == "⚙️ System Controls":
        show_system_controls_page(dashboard)
    elif page == "📊 Reports":
        show_reports_page(dashboard)

def show_overview_page(dashboard):
    """Overview dashboard with key metrics"""
    st.header("📊 System Overview")
    
    # Fetch data (datetime parsing is now handled in the dashboard methods)
    alerts_df = dashboard.get_alerts_data()
    ml_alerts_df = dashboard.get_ml_alerts_data()
    
    # Metrics row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        total_alerts = len(alerts_df) + len(ml_alerts_df)
        st.metric("🚨 Total Alerts", total_alerts)
    
    with col2:
        high_severity = len(alerts_df[alerts_df['severity'] == 'High']) if not alerts_df.empty else 0
        st.metric("🔴 High Severity", high_severity)
    
    with col3:
        ml_anomalies = len(ml_alerts_df) if not ml_alerts_df.empty else 0
        st.metric("🤖 ML Detections", ml_anomalies)
    
    with col4:
        blocked_ips = len(ml_alerts_df[ml_alerts_df['action_taken'] == 'IP_BLOCKED']) if not ml_alerts_df.empty else 0
        st.metric("🚫 Blocked IPs", blocked_ips)
    
    # Charts row
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🎯 Threat Types Distribution")
        if not alerts_df.empty:
            threat_counts = alerts_df['threat_type'].value_counts()
            fig = px.pie(values=threat_counts.values, names=threat_counts.index, 
                        color_discrete_sequence=px.colors.qualitative.Set3)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No threat data available")
    
    with col2:
        st.subheader("📈 Alerts Timeline")
        if not alerts_df.empty and 'timestamp' in alerts_df.columns:
            # Check if timestamp column was successfully parsed
            if pd.api.types.is_datetime64_any_dtype(alerts_df['timestamp']):
                hourly_counts = alerts_df.set_index('timestamp').resample('H').size()
                fig = px.line(x=hourly_counts.index, y=hourly_counts.values,
                             labels={'x': 'Time', 'y': 'Alert Count'})
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("Timestamp data could not be parsed for timeline")
        else:
            st.info("No timeline data available")
    
    # Recent alerts
    st.subheader("🔔 Recent Alerts")
    if not alerts_df.empty:
        recent_alerts = alerts_df.head(10)
        st.dataframe(recent_alerts[['timestamp', 'src_ip', 'threat_type', 'severity', 'detected_by']], 
                    use_container_width=True)
    else:
        st.info("No recent alerts")

def show_alerts_page(dashboard):
    """Real-time alerts monitoring page"""
    st.header("🚨 Real-time Alert Monitor")
    
    # Fetch alerts (datetime parsing is now handled in the dashboard methods)
    alerts_df = dashboard.get_alerts_data()
    ml_alerts_df = dashboard.get_ml_alerts_data()
    
    # Filters
    col1, col2, col3 = st.columns(3)
    
    with col1:
        severity_filter = st.selectbox("🎚️ Filter by Severity", 
                                     ["All", "High", "Medium", "Low"])
    
    with col2:
        detection_filter = st.selectbox("🔍 Filter by Detection Type", 
                                      ["All", "signature", "rule", "ml"])
    
    with col3:
        time_filter = st.selectbox("⏰ Time Range", 
                                 ["All Time", "Last Hour", "Last 24 Hours", "Last Week"])
    
    # Apply filters
    filtered_alerts = alerts_df.copy()
    
    if severity_filter != "All" and not filtered_alerts.empty:
        filtered_alerts = filtered_alerts[filtered_alerts['severity'] == severity_filter]
    
    if detection_filter != "All" and not filtered_alerts.empty:
        filtered_alerts = filtered_alerts[filtered_alerts['detected_by'] == detection_filter]
    
    # Display alerts
    if not filtered_alerts.empty:
        st.subheader(f"📋 Alerts ({len(filtered_alerts)} total)")
        
        # Alert cards for high severity
        high_alerts = filtered_alerts[filtered_alerts['severity'] == 'High']
        if not high_alerts.empty:
            st.subheader("🔴 High Severity Alerts")
            for _, alert in high_alerts.head(5).iterrows():
                with st.container():
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.write(f"**IP:** {alert['src_ip']}")
                    with col2:
                        st.write(f"**Threat:** {alert['threat_type']}")
                    with col3:
                        st.write(f"**Time:** {alert['timestamp']}")
                    with col4:
                        st.write(f"**Action:** {alert['action_taken']}")
                    st.divider()
        
        # Full alerts table
        st.subheader("📊 All Alerts")
        st.dataframe(filtered_alerts, use_container_width=True)
    else:
        st.info("No alerts match the selected filters")
    
    # ML Alerts section
    if not ml_alerts_df.empty:
        st.subheader("🤖 ML Anomaly Detection Alerts")
        st.dataframe(ml_alerts_df[['src_ip', 'dst_ip', 'anomaly_score', 'model_prediction', 
                                  'action_taken', 'created_at']], use_container_width=True)

def show_ml_detection_page(dashboard):
    """ML detection and testing page"""
    st.header("🤖 Machine Learning Detection")
    
    # ML API Status
    try:
        response = requests.get(f"{dashboard.api_base}/ml-stats", timeout=5)
        if response.status_code == 200:
            ml_stats = response.json().get('ml_statistics', {})
            
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("📊 Total ML Alerts", ml_stats.get('total_ml_alerts', 0))
            with col2:
                st.metric("📅 Today's Alerts", ml_stats.get('alerts_today', 0))
            with col3:
                st.metric("🚫 Blocked Today", ml_stats.get('blocked_today', 0))
            with col4:
                st.metric("📈 Avg Score", ml_stats.get('avg_anomaly_score_today', 0))
        else:
            st.warning("ML stats not available")
    except Exception as e:
        st.error(f"Error fetching ML stats: {e}")
    
    # Test ML Detection
    st.subheader("🧪 Test ML Detection")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Simple ML Test**")
        
        # Pre-defined test samples
        test_option = st.selectbox("Select test sample:", 
                                 ["Normal Traffic", "DDoS Attack", "Port Scan", "Custom"])
        
        if test_option == "Normal Traffic":
            test_data = {
                "flow_duration": 0.5,
                "total_fwd_packets": 20,
                "total_backward_packets": 15,
                "flow_bytes_sec": 5000,
                "flow_packets_sec": 70,
                "src_ip": "192.168.1.100"
            }
        elif test_option == "DDoS Attack":
            test_data = {
                "flow_duration": 15.0,
                "total_fwd_packets": 1000,
                "total_backward_packets": 5,
                "flow_bytes_sec": 100000,
                "flow_packets_sec": 800,
                "src_ip": "192.168.100.50"
            }
        elif test_option == "Port Scan":
            test_data = {
                "flow_duration": 0.01,
                "total_fwd_packets": 1,
                "total_backward_packets": 0,
                "flow_bytes_sec": 500,
                "flow_packets_sec": 100,
                "src_ip": "192.168.200.25"
            }
        else:
            test_data = {}
        
        if test_option != "Custom":
            st.json(test_data)
        
        if st.button("🚀 Test Simple ML Model", key="simple_ml"):
            try:
                response = requests.post(f"{dashboard.api_base}/ml-predict", 
                                       json=test_data, timeout=10)
                if response.status_code == 200:
                    result = response.json()
                    
                    if result.get('is_anomaly'):
                        st.error(f"🚨 ANOMALY DETECTED! Score: {result.get('anomaly_score', 0):.3f}")
                    else:
                        st.success(f"✅ Normal traffic. Score: {result.get('anomaly_score', 0):.3f}")
                    
                    st.json(result)
                else:
                    st.error(f"API Error: {response.status_code}")
            except Exception as e:
                st.error(f"Error: {e}")
    
    with col2:
        st.write("**Advanced ML Test**")
        
        if st.button("🚀 Test Advanced ML Model", key="advanced_ml"):
            try:
                response = requests.post(f"{dashboard.api_base}/ml-predict-advanced", 
                                       json=test_data, timeout=10)
                if response.status_code == 200:
                    result = response.json()
                    
                    if result.get('anomaly_detected'):
                        st.error(f"🚨 ANOMALY DETECTED! Score: {result.get('anomaly_score', 0):.3f}")
                    else:
                        st.success(f"✅ Normal traffic. Score: {result.get('anomaly_score', 0):.3f}")
                    
                    st.json(result)
                else:
                    st.error(f"API Error: {response.status_code}")
            except Exception as e:
                st.error(f"Error: {e}")
    
    # Manual ML Detection Cycle
    st.subheader("🔄 Manual Detection")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🎯 Run ML Detection Cycle"):
            with st.spinner("Running ML detection..."):
                try:
                    response = requests.post(f"{dashboard.api_base}/run-ml-detection", timeout=30)
                    if response.status_code == 200:
                        result = response.json()
                        st.success("✅ ML detection cycle completed")
                        st.json(result)
                    else:
                        st.error(f"Error: {response.status_code}")
                except Exception as e:
                    st.error(f"Error: {e}")
    
    with col2:
        if st.button("🧪 Test Model Variety"):
            try:
                response = requests.get(f"{dashboard.api_base}/test-model-variety", timeout=10)
                if response.status_code == 200:
                    result = response.json()
                    st.success("✅ Model variety test completed")
                    st.json(result)
                else:
                    st.error(f"Error: {response.status_code}")
            except Exception as e:
                st.error(f"Error: {e}")

def show_threat_analysis_page(dashboard):
    """Threat analysis and signature testing"""
    st.header("🔍 Threat Analysis & Signature Detection")
    
    # Signature Testing
    st.subheader("🎯 Test Signature Detection")
    
    payload_examples = {
        "SQL Injection": "' OR '1'='1",
        "XSS Attack": "<script>alert('XSS')</script>",
        "Command Injection": "; cat /etc/passwd",
        "Path Traversal": "../../../etc/passwd",
        "Custom": ""
    }
    
    col1, col2 = st.columns(2)
    
    with col1:
        attack_type = st.selectbox("Select attack type:", list(payload_examples.keys()))
        
        if attack_type == "Custom":
            payload = st.text_area("Enter custom payload:")
        else:
            payload = st.text_area("Payload:", value=payload_examples[attack_type])
        
        src_ip = st.text_input("Source IP:", value="192.168.1.100")
    
    with col2:
        if st.button("🔍 Test Signature Detection"):
            if payload:
                try:
                    test_data = {
                        "payload": payload,
                        "src_ip": src_ip,
                        "timestamp": datetime.now().isoformat()
                    }
                    
                    response = requests.post(f"{dashboard.api_base}/scan", 
                                           json=test_data, timeout=10)
                    
                    if response.status_code == 200:
                        result = response.json()
                        
                        if result.get('status') == 'threat_detected':
                            details = result.get('details', {})
                            st.error("🚨 THREAT DETECTED!")
                            st.write(f"**Threat Type:** {details.get('threat', 'Unknown')}")
                            st.write(f"**Severity:** {details.get('severity', 'Unknown')}")
                            st.write(f"**Pattern:** {details.get('matched_pattern', 'Unknown')}")
                        else:
                            st.success("✅ Payload appears clean")
                    else:
                        st.error(f"API Error: {response.status_code}")
                        
                except Exception as e:
                    st.error(f"Error: {e}")
            else:
                st.warning("Please enter a payload to test")
    
    # Rule Engine Testing
    st.subheader("⚙️ Rule Engine Detection")
    
    if st.button("🔄 Run Rule Engine"):
        try:
            with st.spinner("Running rule engine detection..."):
                response = requests.get(f"{dashboard.api_base}/run-rule-engine", timeout=30)
                
                if response.status_code == 200:
                    result = response.json()
                    st.success(f"✅ Rule engine completed: {result.get('total_alerts_generated', 0)} alerts generated")
                    
                    if result.get('alerts'):
                        st.subheader("📋 Generated Alerts")
                        alerts_df = pd.DataFrame(result['alerts'])
                        st.dataframe(alerts_df, use_container_width=True)
                else:
                    st.error(f"Error: {response.status_code}")
                    
        except Exception as e:
            st.error(f"Error: {e}")

def show_system_controls_page(dashboard):
    """System controls and monitoring"""
    st.header("⚙️ System Controls")
    
    # API Health Status
    st.subheader("🏥 System Health")
    
    is_healthy, health_data = dashboard.check_api_health()
    
    if is_healthy:
        st.success("✅ All systems operational")
        
        services = health_data.get('services', {})
        ml_details = health_data.get('ml_details', {})
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Core Services:**")
            for service, status in services.items():
                icon = "✅" if status else "❌"
                st.write(f"{icon} {service.replace('_', ' ').title()}: {status}")
        
        with col2:
            st.write("**ML Services:**")
            for detail, status in ml_details.items():
                icon = "✅" if status else "❌"
                st.write(f"{icon} {detail.replace('_', ' ').title()}: {status}")
    else:
        st.error("❌ System health check failed")
        st.write(f"Error: {health_data}")
    
    # System Controls
    st.subheader("🎛️ Control Panel")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🔄 Restart Services"):
            st.info("Service restart would be handled by system admin")
    
    with col2:
        if st.button("🧹 Clear Logs"):
            st.info("Log clearing would be handled by system admin")
    
    with col3:
        if st.button("📊 Export Data"):
            st.info("Data export functionality would be implemented here")
    
    # Database Status
    st.subheader("🗄️ Database Status")
    
    try:
        # Test database connections
        alerts_count = len(dashboard.get_alerts_data(limit=1))
        ml_alerts_count = len(dashboard.get_ml_alerts_data(limit=1))
        network_data_count = len(dashboard.get_network_data(limit=1))
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("📊 Alerts Table", "✅ Connected")
        with col2:
            st.metric("🤖 ML Alerts Table", "✅ Connected")
        with col3:
            st.metric("🌐 Network Data Table", "✅ Connected")
            
    except Exception as e:
        st.error(f"Database connection error: {e}")

def show_reports_page(dashboard):
    """Reports and analytics page"""
    st.header("📊 Security Reports & Analytics")
    
    # Fetch data (datetime parsing is now handled in the dashboard methods)
    alerts_df = dashboard.get_alerts_data(limit=500)
    ml_alerts_df = dashboard.get_ml_alerts_data(limit=500)
    
    # Time range selector
    time_range = st.selectbox("📅 Select Time Range", 
                             ["Last 24 Hours", "Last Week", "Last Month", "All Time"])
    
    if not alerts_df.empty:
        # Threat trends
        st.subheader("📈 Threat Trends")
        
        # Check if timestamp column was successfully parsed
        if 'timestamp' in alerts_df.columns and pd.api.types.is_datetime64_any_dtype(alerts_df['timestamp']):
            # Daily trend
            daily_counts = alerts_df.set_index('timestamp').resample('D').size()
            fig = px.bar(x=daily_counts.index, y=daily_counts.values,
                        labels={'x': 'Date', 'y': 'Alert Count'},
                        title="Daily Alert Trends")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.warning("Timestamp data could not be parsed for trend analysis")
        
        # Threat type analysis
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("🎯 Top Threat Types")
            threat_counts = alerts_df['threat_type'].value_counts().head(10)
            fig = px.bar(x=threat_counts.values, y=threat_counts.index, orientation='h',
                        labels={'x': 'Count', 'y': 'Threat Type'})
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("🌍 Top Source IPs")
            ip_counts = alerts_df['src_ip'].value_counts().head(10)
            fig = px.bar(x=ip_counts.values, y=ip_counts.index, orientation='h',
                        labels={'x': 'Count', 'y': 'Source IP'})
            st.plotly_chart(fig, use_container_width=True)
        
        # Severity distribution
        st.subheader("⚠️ Severity Analysis")
        severity_counts = alerts_df['severity'].value_counts()
        fig = px.pie(values=severity_counts.values, names=severity_counts.index,
                    color_discrete_map={'High': '#ff4444', 'Medium': '#ffaa44', 'Low': '#44ff44'})
        st.plotly_chart(fig, use_container_width=True)
    
    else:
        st.info("No data available for reports")
    
    # Export functionality
    st.subheader("📤 Export Reports")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📄 Export CSV"):
            if not alerts_df.empty:
                csv = alerts_df.to_csv(index=False)
                st.download_button(
                    label="⬇️ Download CSV",
                    data=csv,
                    file_name=f"idps_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
            else:
                st.warning("No data to export")
    
    with col2:
        if st.button("📊 Export JSON"):
            if not alerts_df.empty:
                json_data = alerts_df.to_json(orient='records')
                st.download_button(
                    label="⬇️ Download JSON",
                    data=json_data,
                    file_name=f"idps_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
            else:
                st.warning("No data to export")
    
    with col3:
        if st.button("📈 Generate Report"):
            st.info("Detailed report generation would be implemented here")

if __name__ == "__main__":
    main()