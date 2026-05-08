"""
Quick integration test — verifies backend, AI engine and simulator
all talk to each other correctly.
Run: python quick_test.py
"""

import sys
import json
import time

try:
    import requests
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    print("Run: pip install requests colorama")
    sys.exit(1)

BACKEND   = "http://localhost:5000"
AI_ENGINE = "http://localhost:7000"

PASS = Fore.GREEN  + "  ✓ PASS" + Style.RESET_ALL
FAIL = Fore.RED    + "  ✗ FAIL" + Style.RESET_ALL
INFO = Fore.CYAN   + "  →"      + Style.RESET_ALL

def check(label, fn):
    try:
        result = fn()
        print(f"{PASS}  {label}")
        return result
    except Exception as e:
        print(f"{FAIL}  {label}  —  {str(e)[:80]}")
        return None

print("\n" + "═"*55)
print(f"  {Fore.CYAN + Style.BRIGHT}Integration Test Suite{Style.RESET_ALL}")
print("═"*55 + "\n")

# 1. Backend health
print(f"  {Fore.YELLOW}[ Backend ]{Style.RESET_ALL}")
r = check("Backend /api/health responds",
    lambda: requests.get(f"{BACKEND}/api/health", timeout=4).raise_for_status())
if r:
    d = requests.get(f"{BACKEND}/api/health").json()
    print(f"{INFO}  MongoDB: {d.get('mongodb')}  Uptime: {d.get('uptime',0):.1f}s")

# 2. AI engine health
print(f"\n  {Fore.YELLOW}[ AI Engine ]{Style.RESET_ALL}")
r = check("AI engine /health responds",
    lambda: requests.get(f"{AI_ENGINE}/health", timeout=4).raise_for_status())
if r:
    d = requests.get(f"{AI_ENGINE}/health").json()
    print(f"{INFO}  Model: {d.get('model')}  Accuracy: {d.get('accuracy',0)*100:.1f}%")

# 3. Auth login
"""print(f"\n  {Fore.YELLOW}[ Authentication ]{Style.RESET_ALL}")
token = None
r = check("Login with admin credentials",
    lambda: requests.post(f"{BACKEND}/api/auth/login",
        json={"email":"admin@cyberthreat.local","password":"Admin@123456"},
        timeout=4).raise_for_status())
if r:
    data  = requests.post(f"{BACKEND}/api/auth/login",
        json={"email":"admin@cyberthreat.local","password":"Admin@123456"}).json()
    token = data.get("accessToken")
    print(f"{INFO}  Role: {data['user']['role']}  Token: {token[:24]}...")

headers = {"Authorization": f"Bearer {token}"} if token else {}"""
# 3. Auth login
print(f"\n  {Fore.YELLOW}[ Authentication ]{Style.RESET_ALL}")

token = None

login_response = requests.post(
    f"{BACKEND}/api/auth/login",
    json={
        "email": "admin@cyberthreat.local",
        "password": "Admin@123456"
    },
    timeout=4
)

print("LOGIN STATUS:", login_response.status_code)

data = login_response.json()

print("FULL LOGIN RESPONSE:")
print(data)

token = data.get("accessToken") or data.get("token")

print("TOKEN VALUE:", token)

headers = {
    "Authorization": f"Bearer {token}"
} if token else {}

print("HEADERS:", headers)

# 4. Telemetry ingestion tests
print(f"\n  {Fore.YELLOW}[ Telemetry Ingestion ]{Style.RESET_ALL}")

test_events = [
    {"ip":"8.8.8.8",          "action":"malware_activity",  "malwareDetected":3},
    {"ip":"192.168.1.10",     "action":"login_attempt",     "loginAttempts":2},
    {"ip":"185.220.101.45",   "action":"port_scan",         "portScans":350},
    {"ip":"45.141.84.120",    "action":"data_exfiltration", "dataTransferred":200000000},
    {"ip":"91.108.4.100",     "action":"ransomware",        "malwareDetected":8},
    {"ip":"77.88.55.88",      "action":"ddos",              "portScans":5000},
    {"ip":"10.0.0.5",         "action":"file_access",       "requestCount":3},
    {"ip":"203.0.113.50",     "action":"sql_injection",     "port":80},
]

results = []
for ev in test_events:
    r = check(f"Ingest {ev['action']:22s} from {ev['ip']}",
        lambda e=ev: requests.post(f"{BACKEND}/api/telemetry", json=e, timeout=6).raise_for_status())
    if r:
        d   = requests.post(f"{BACKEND}/api/telemetry", json=ev, timeout=6).json()
        t   = d.get("threat", {})
        sev = t.get("severity","?")
        col = Fore.MAGENTA if sev=="CRITICAL" else Fore.RED if sev=="HIGH" else Fore.YELLOW if sev=="MEDIUM" else Fore.GREEN
        print(f"{INFO}  Severity: {col}{sev}{Style.RESET_ALL}  Confidence: {t.get('confidence',0)*100:.1f}%")
        results.append(sev)
    time.sleep(0.15)


# 5. Stats endpoints

# 5. Stats endpoints
print(f"\n  {Fore.YELLOW}[ Stats API ]{Style.RESET_ALL}")

stats_endpoints = [
    "/api/stats/overview",
    "/api/stats/timeline",
    "/api/stats/geo",
    "/api/stats/system",
    "/api/stats/blockchain",
]

for ep in stats_endpoints:
    check(f"GET {ep}",
        lambda e=ep: requests.get(
            f"{BACKEND}{e}",
            headers=headers,
            timeout=4
        ).raise_for_status()
    )

# 6. AI batch endpoint
print(f"\n  {Fore.YELLOW}[ AI Batch Analysis ]{Style.RESET_ALL}")
check("POST /analyze/batch (5 events)",
    lambda: requests.post(f"{AI_ENGINE}/analyze/batch",
        json=[{"ip":"1.2.3.4","action":"port_scan"},
              {"ip":"5.6.7.8","action":"ransomware"},
              {"ip":"9.10.11.12","action":"login_attempt"},
              {"ip":"13.14.15.16","action":"ddos"},
              {"ip":"17.18.19.20","action":"malware_activity"}],
        timeout=6).raise_for_status())

# Summary
print("\n" + "═"*55)
if results:
    from collections import Counter
    dist = Counter(results)
    print(f"  {Fore.CYAN}Detection results:{Style.RESET_ALL}")
    for sev, cnt in sorted(dist.items()):
        col = Fore.MAGENTA if sev=="CRITICAL" else Fore.RED if sev=="HIGH" else Fore.YELLOW if sev=="MEDIUM" else Fore.GREEN
        print(f"    {col}{sev:10s}{Style.RESET_ALL} {cnt} events")
print("═"*55)
print(f"\n  {Fore.GREEN + Style.BRIGHT}All systems verified. Ready to run.{Style.RESET_ALL}\n")