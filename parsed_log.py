import re
import pandas as pd
import os

def parse_linux_log_v2(file_path):
    entries = []

    with open(file_path, 'r') as file:
        for line in file:
            # Match lines with this format:
            # Jun 15 02:04:59 hostname sshd(pam_unix)[1234]: message
            match = re.match(r'^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+\S+\s+([\w\-/]+(?:\([\w\-]+\))?)\[\d+\]:\s+(.*)', line)
            if match:
                month, day, time, service, message = match.groups()
                timestamp = f"{month} {day} {time}"

                # Extract user and IP
                user = None
                ip = None

                user_match = re.search(r'user(?:name)?=([\w\-]+)', message) or re.search(r'for user (\w+)', message)
                if user_match:
                    user = user_match.group(1)

                ip_match = re.search(r'rhost=([\d.]+)', message) or re.search(r'from ([\d.]+)', message)
                if ip_match:
                    ip = ip_match.group(1)

                entries.append({
                    'timestamp': timestamp,
                    'service': service,
                    'event': message,
                    'username': user,
                    'ip': ip
                })

    # Convert to DataFrame
    df = pd.DataFrame(entries)

    # Ensure output folder exists
    os.makedirs("data", exist_ok=True)
    df.to_csv("parsed_logs.csv", index=False)
    print(f"[+] Parsed {len(df)} entries. Saved to data/parsed_linux_logs.csv")
    return df

# Run the parser
if __name__ == "__main__":
    parse_linux_log_v2("Linux_2k.log")
