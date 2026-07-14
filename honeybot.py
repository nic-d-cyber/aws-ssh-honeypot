import os
import socket
import sys
import threading
import time
import logging
import json
import subprocess
from datetime import datetime, timezone
from collections import defaultdict, deque
import paramiko

# Logging and storage setup
LOG_DIR = "/home/ubuntu/honeybot_files"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)
    
LOG_FILE = os.path.join(LOG_DIR, "honeybot.jsonl")
HOST_KEY_PATH = os.path.join(LOG_DIR, "honeybot_rsa.key")

# System logger configuration
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Parameters
BIND_ADDR = "0.0.0.0"
BIND_PORT = 22
FAKE_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"

# Mitigation System Variables
BRUTEFORCE_WINDOW = 60  # seconds
BRUTEFORCE_THRESHOLD = 5  # login attempts
BAN_ENABLED = True

attempts_by_ip = defaultdict(deque)
banned_ips = set()
lock = threading.Lock()

def log_event(event: dict):
    """Writes a structured JSON event to the logs."""
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(event) + "\n")
    except Exception as e:
        logging.error(f"Failed to write log event: {e}")

def ban_ip(ip: str, reason: str):
    """Bans an IP address using system iptables."""
    with lock:
        if ip in banned_ips:
            return
        banned_ips.add(ip)
    
    log_event({"type": "BAN", "ip": ip, "reason": reason})
    logging.warning(f"[!] IP BANNED: {ip} | Reason: {reason}")
    
    if BAN_ENABLED:
        try:
            subprocess.run(
                ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True
            )
        except Exception as e:
            logging.error(f"Failed to apply iptables block rule for {ip}: {e}")

def register_attempt(ip: str):
    """Registers connection attempts and triggers bans if threshold is exceeded."""
    now = time.time()
    with lock:
        dq = attempts_by_ip[ip]
        dq.append(now)
        # Clean up old timestamps outside the analysis window
        while dq and now - dq[0] > BRUTEFORCE_WINDOW:
            dq.popleft()
        
        attempt_count = len(dq)
        
    if attempt_count >= BRUTEFORCE_THRESHOLD:
        ban_ip(ip, f"Brute force detected: {attempt_count} attempts within {BRUTEFORCE_WINDOW}s")

class HoneypotServer(paramiko.ServerInterface):
    """Paramiko Interface to simulate an open SSH server and harvest credentials."""
    def __init__(self, client_ip):
        self.client_ip = client_ip

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        log_event({
            "type": "LOGIN_ATTEMPT", 
            "ip": self.client_ip, 
            "username": username, 
            "password": password
        })
        logging.info(f"[CRACK-ATTEMPT] {self.client_ip} tried credentials '{username}':'{password}'")
        register_attempt(self.client_ip)
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

def handle_connection(client_sock, addr):
    ip = addr[0]
    
    if ip in banned_ips:
        client_sock.close()
        return
        
    log_event({"type": "CONNECTION", "ip": ip, "port": addr[1]})
    logging.info(f"[CONN] Inbound connection from {ip}:{addr[1]}")
    
    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = FAKE_BANNER
        
        host_key = paramiko.RSAKey(filename=HOST_KEY_PATH)
        transport.add_server_key(host_key)
        
        server = HoneypotServer(client_ip=ip)
        try:
            transport.start_server(server=server)
        except paramiko.SSHException:
            logging.info(f"[DISCONN] Connection closed prematurely by {ip}")
            return
            
        chan = transport.accept(20)
        if chan is not None:
            time.sleep(1)
            chan.close()
            
    except Exception as e:
        logging.debug(f"Socket issue with {ip}: {e}")
    finally:
        try:
            client_sock.close()
        except Exception:
            pass

def main():
    if not os.path.exists(HOST_KEY_PATH):
        logging.info("[*] Host key not found. Generating new RSA Key...")
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(HOST_KEY_PATH)
        
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        sock.bind((BIND_ADDR, BIND_PORT))
        sock.listen(100)
        logging.info(f"[*] HoneyBot Active! Simulating port {BIND_PORT}...")
    except Exception as e:
        logging.error(f"[-] Failed to bind socket to port {BIND_PORT}: {e}")
        sys.exit(1)

    while True:
        try:
            client_sock, addr = sock.accept()
            threading.Thread(
                target=handle_connection, 
                args=(client_sock, addr),
                daemon=True
            ).start()
        except KeyboardInterrupt:
            logging.info("\n[*] Shutting down HoneyBot gracefully.")
            break
        except Exception as e:
            logging.error(f"[-] Socket accept failed: {e}")

if __name__ == "__main__":
    main()
```
eof

```python:HoneyBot Log Analyzer:honeybot_analysis.py
import os
import json
from collections import Counter

LOG_FILE_PATH = "/home/ubuntu/honeybot_files/honeybot.jsonl"

def analyze_jsonl_logs(file_path):
    if not os.path.exists(file_path):
        print(f"[-] Error: Log file not found at {file_path}")
        return

    print("=" * 65)
    print("        HONEYBOT THREAT INTELLIGENCE AND ANALYTICS REPORT        ")
    print("=" * 65)

    connections_count = 0
    login_attempts = 0
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
                    
                elif event_type == "BAN":
                    ban_events += 1
                    
            except json.JSONDecodeError:
                continue

    # Main Metrics
    print(f"[*] Total Raw Connections:           {connections_count}")
    print(f"[*] Captured Brute-Force Attempts:   {login_attempts}")
    print(f"[*] IP Addresses Banned:             {ban_events}")
    print("-" * 65)

    # Top Threat Actors IPs
    if ips:
        ip_counts = Counter(ips)
        print("\n[+] TOP 5 ACTIVE THREAT IPS:")
        for idx, (ip, count) in enumerate(ip_counts.most_common(5), 1):
            print(f"    {idx}. {ip:<15} - {count} occurrences")
    else:
        print("\n[-] No IP data found in registry logs.")

    # Top Target Accounts
    if usernames:
        user_counts = Counter(usernames)
        print("\n[+] TOP 5 TARGETED USERNAMES:")
        for idx, (user, count) in enumerate(user_counts.most_common(5), 1):
            print(f"    {idx}. '{user}' - {count} times")
    else:
        print("\n[-] No authentication attempts captured.")

    # Top Passwords Tried
    if passwords:
        pwd_counts = Counter(passwords)
        print("\n[+] TOP 5 TESTED PASSWORDS:")
        for idx, (pwd, count) in enumerate(pwd_counts.most_common(5), 1):
            print(f"    {idx}. '{pwd}' - {count} times")

    # Top Credential Combinations
    if credentials:
        cred_counts = Counter(credentials)
        print("\n[+] TOP 5 CREDENTIAL STUFFING PAIRS:")
        for idx, ((user, pwd), count) in enumerate(cred_counts.most_common(5), 1):
            print(f"    {idx}. {user}:{pwd:<15} - {count} attempts")

    print("=" * 65)

if __name__ == "__main__":
    analyze_jsonl_logs(LOG_FILE_PATH)
```
eof


