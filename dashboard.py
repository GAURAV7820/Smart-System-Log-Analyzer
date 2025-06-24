import streamlit as st
import pandas as pd

# Set page config (must be FIRST)
st.set_page_config(page_title="System Log Threat Dashboard", layout="wide")

# App load confirmation
st.success("✅ App Loaded")

# Page title
st.title("System Log Threat Dashboard")

# === Load and process log data ===
try:
    df_logs = pd.read_csv("parsed_logs.csv")

    # Filter failed login events
    failed_logins = df_logs[df_logs['event'].str.contains("authentication failure", case=False, na=False)]

    st.markdown(f"🔍 **Failed login entries:** `{len(failed_logins)}`")

    # Group by IP
    failed_by_ip = failed_logins['ip'].value_counts().reset_index()
    failed_by_ip.columns = ['IP Address', 'Failed Attempts']

    # Suspicious IPs (e.g. brute-force threshold >= 10)
    suspicious_ips_df = failed_by_ip[failed_by_ip['Failed Attempts'] >= 10]

    # Detect proper username column
    user_col = 'user'
    if 'username' in df_logs.columns:
        user_col = 'username'

    # Join for usernames and timestamps if available
    if user_col in df_logs.columns and 'timestamp' in df_logs.columns:
        latest_attempts = (
            failed_logins.groupby('ip')
            .agg({
                user_col: 'last',
                'timestamp': 'last'
            })
            .reset_index()
            .rename(columns={'ip': 'IP Address', user_col: 'Username', 'timestamp': 'Last Attempt'})
        )

        # Correct indentation here
        threat_df = pd.merge(failed_by_ip, latest_attempts, on="IP Address", how="left")

        # Convert Last Attempt to string for display/export
        threat_df["Last Attempt"] = threat_df["Last Attempt"].astype(str)

    else:
        # Fallback if user/timestamp are missing
        threat_df = failed_by_ip.copy()
        threat_df['Username'] = 'Unknown'
        threat_df['Last Attempt'] = 'N/A'

    # === Dashboard Metrics ===
    total_failed_logins = len(failed_logins)
    total_suspicious_ips = len(suspicious_ips_df)

    col1, col2 = st.columns(2)
    col1.metric("Total Failed Logins", total_failed_logins)
    col2.metric("Suspicious IPs (≥10 Attempts)", total_suspicious_ips)

    # === Bar Chart ===
    st.subheader("📊 Failed Attempts per IP")
    chart_data = threat_df.set_index("IP Address")[["Failed Attempts"]]
    st.bar_chart(chart_data)

    # === Threat Details Table ===
    st.subheader("🕵️ Threat Details")
    st.dataframe(threat_df)

except FileNotFoundError:
    st.error("❌ Log file 'parsed_logs.csv' not found.")
except Exception as e:
    st.error(f"❌ An error occurred: {e}")
