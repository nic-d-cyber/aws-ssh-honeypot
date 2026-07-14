import os
import json
from collections import Counter

# Default path on the AWS EC2 instance
DEFAULT_LOG_PATH = "/home/ubuntu/honeybot_files/honeybot.jsonl"
# Local fallback in case you download the logs to your computer
LOCAL_LOG_PATH = "honeybot.jsonl"

def analyze_honeybot_logs(file_path):
    if not os.path.exists(file_path):
        print(f"[-] Error: Log file not found at {file_path}")
        return False

    print("=" * 65)
    print("         HONEYBOT THREAT INTELLIGENCE & ANALYTICS REPORT        ")
    print("=" * 65)

    connections_count = 0
    login_attempts = 0
    pubkey_attempts = 0
    ban_events = 0

    ips = []
    usernames = []
    passwords = []
    credentials = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            try:
                event = json.loads(line.strip())
                event_type = event.get("type")
                
                if event_type == "CONNECTION":
                    connections_count += 1
                    ips.append(event.get("ip"))
                    
                elif event_type == "LOGIN_ATTEMPT":
                    login_attempts += 1
                    ip = event.get("ip")
                    user = event.get("username")
                    pwd = event.get("password")
                    
                    ips.append(ip)
                    usernames.append(user)
                    passwords.append(pwd)
                    credentials.append((user, pwd))
                    
                elif event_type == "PUBKEY_ATTEMPT":
                    pubkey_attempts += 1
                    ips.append(event.get("ip"))
                    usernames.append(event.get("username"))
                    
                elif event_type == "BAN":
                    ban_events += 1
                    
            except json.JSONDecodeError:
                continue

    # Summary Metrics
    print(f"[*] Total Raw Connections:           {connections_count}")
    print(f"[*] Captured Password Attempts:      {login_attempts}")
    print(f"[*] Captured Key-Auth Attempts:      {pubkey_attempts}")
    print(f"[*] Automated IP Bans Triggered:     {ban_events}")
    print("-" * 65)

    # Top Threat Source IPs
    if ips:
        ip_counts = Counter(ips)
        print("\n[+] TOP 5 ACTIVE ATTACKER IPs:")
        for idx, (ip, count) in enumerate(ip_counts.most_common(5), 1):
            print(f"    {idx}. {ip:<15} - {count} hits")
    else:
        print("\n[-] No IP metadata found in the logs.")

    # Top Targeted Usernames
    if usernames:
        user_counts = Counter(usernames)
        print("\n[+] TOP 5 TARGETED USERNAMES:")
        for idx, (user, count) in enumerate(user_counts.most_common(5), 1):
            print(f"    {idx}. '{user}' - Targeted {count} times")
    else:
        print("\n[-] No authentication attempts captured.")

    # Top Tested Passwords
    if passwords:
        pwd_counts = Counter(passwords)
        print("\n[+] TOP 5 TESTED PASSWORDS:")
        for idx, (pwd, count) in enumerate(pwd_counts.most_common(5), 1):
            print(f"    {idx}. '{pwd}' - Tried {count} times")

    # Top Credential Stuffing Combinations
    if credentials:
        cred_counts = Counter(credentials)
        print("\n[+] TOP 5 CREDENTIAL PAIRS (User:Password):")
        for idx, ((user, pwd), count) in enumerate(cred_counts.most_common(5), 1):
            print(f"    {idx}. {user}:{pwd:<20} - {count} attempts")

    print("=" * 65)
    return True

if __name__ == "__main__":
    # Check AWS path first, fallback to local directory if not found
    if os.path.exists(DEFAULT_LOG_PATH):
        analyze_honeybot_logs(DEFAULT_LOG_PATH)
    elif os.path.exists(LOCAL_LOG_PATH):
        print(f"[*] Analyzing local log file: {LOCAL_LOG_PATH}")
        analyze_honeybot_logs(LOCAL_LOG_PATH)
    else:
        print(f"[-] Error: Could not find '{DEFAULT_LOG_PATH}' or local '{LOCAL_LOG_PATH}'")
        print("[*] Please make sure your Honeypot has generated logs before running.")
```
eof
