# === Failed Login Processing ===
failed_logins = df_logs[df_logs['event'].str.contains("authentication failure", case=False, na=False)]
failed_by_ip = failed_logins['ip'].value_counts().reset_index()
failed_by_ip.columns = ['IP Address', 'Failed Attempts']

# Detect suspicious IPs (≥10 attempts)
suspicious_ips_df = failed_by_ip[failed_by_ip['Failed Attempts'] >= 10]

# Determine correct user column
user_col = 'username' if 'username' in df_logs.columns else 'user'

# Add latest user and timestamp info
if user_col in df_logs.columns and 'timestamp' in df_logs.columns:
    latest_info = (
        failed_logins.groupby('ip')
        .agg({
            user_col: 'last',
            'timestamp': 'last'
        })
        .reset_index()
        .rename(columns={'ip': 'IP Address', user_col: 'Username', 'timestamp': 'Last Attempt'})
    )
    threat_df = pd.merge(failed_by_ip, latest_info, on="IP Address", how="left")
    threat_df["Last Attempt"] = threat_df["Last Attempt"].astype(str)
else:
    threat_df = failed_by_ip.copy()
    threat_df['Username'] = 'Unknown'
    threat_df['Last Attempt'] = 'N/A'
