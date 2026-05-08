"""
Cyber Threat Telemetry Simulator
Sends realistic attack telemetry to the backend API.
Run: python telemetry_simulator.py
     python telemetry_simulator.py --scenario ddos
     python telemetry_simulator.py --burst 50
     python telemetry_simulator.py --scenario apt --interval 3
"""

import sys
import time
import random
import argparse
import json
from datetime import datetime

try:
    import requests
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    print("Missing packages. Run: pip install requests colorama")
    sys.exit(1)

# ─── Config ───────────────────────────────────────────────────────────────────
BACKEND_URL = "http://localhost:5000/api/telemetry"
TIMEOUT     = 5

# ─── Color map per severity ───────────────────────────────────────────────────
SEV_COLOR = {
    "CRITICAL": Fore.MAGENTA + Style.BRIGHT,
    "HIGH":     Fore.RED     + Style.BRIGHT,
    "MEDIUM":   Fore.YELLOW  + Style.BRIGHT,
    "LOW":      Fore.GREEN,
    "ERROR":    Fore.RED,
    "INFO":     Fore.CYAN,
}

# ─── IP Pools ─────────────────────────────────────────────────────────────────
EXTERNAL_IPS = [
    "185.220.101.45", "45.141.84.120", "91.108.4.100",
    "77.88.55.88",    "198.51.100.23", "203.0.113.50",
    "104.21.45.67",   "156.89.12.34",  "62.173.145.10",
    "178.73.215.94",  "5.188.86.172",  "149.28.54.89",
    "121.4.120.50",   "167.94.138.30", "80.82.77.33",
    "103.75.190.12",  "194.165.16.78", "45.83.64.10",
    "185.220.100.255","192.42.116.16",
]
INTERNAL_IPS = [
    "192.168.1.10",  "192.168.1.55",  "192.168.0.100",
    "10.0.0.20",     "10.0.1.50",     "172.16.0.10",
    "172.31.255.50", "192.168.2.88",
]
HIGH_RISK_PORTS  = [22, 23, 3389, 445, 135, 139, 1433, 3306, 5432, 6379, 27017]
COMMON_PORTS     = [80, 443, 8080, 8443, 8888, 9090, 5000, 3000]
PROTOCOLS        = ["TCP", "UDP", "HTTP", "HTTPS", "ICMP", "DNS"]

# ─── Attack Scenarios ─────────────────────────────────────────────────────────
SCENARIOS = {

    "normal": {
        "description": "Normal day-to-day traffic — mostly low severity",
        "interval": 3.0,
        "actions": [
            ("login_attempt", 0.35),
            ("file_access",   0.30),
            ("failed_login",  0.15),
            ("port_scan",     0.10),
            ("sql_injection", 0.05),
            ("xss_attempt",   0.05),
        ],
    },

    "ddos": {
        "description": "DDoS attack — high volume, short bursts",
        "interval": 0.25,
        "actions": [
            ("ddos",          0.55),
            ("port_scan",     0.25),
            ("brute_force",   0.20),
        ],
    },

    "apt": {
        "description": "Advanced Persistent Threat — slow, stealthy, critical",
        "interval": 7.0,
        "actions": [
            ("lateral_movement",     0.20),
            ("privilege_escalation", 0.20),
            ("data_exfiltration",    0.20),
            ("c2_communication",     0.20),
            ("dns_tunneling",        0.20),
        ],
    },

    "ransomware": {
        "description": "Ransomware outbreak across internal network",
        "interval": 1.2,
        "actions": [
            ("ransomware",           0.40),
            ("malware_activity",     0.30),
            ("lateral_movement",     0.15),
            ("privilege_escalation", 0.15),
        ],
        "prefer_internal": True,
    },

    "insider": {
        "description": "Insider threat — internal IPs, unusual file access",
        "interval": 5.0,
        "actions": [
            ("file_access",       0.35),
            ("data_exfiltration", 0.30),
            ("failed_login",      0.20),
            ("sql_injection",     0.15),
        ],
        "prefer_internal": True,
    },

    "bruteforce": {
        "description": "Sustained brute-force credential attack",
        "interval": 0.8,
        "actions": [
            ("brute_force",  0.50),
            ("failed_login", 0.35),
            ("port_scan",    0.15),
        ],
    },

    "mixed": {
        "description": "Mixed realistic attack traffic — all types",
        "interval": 2.0,
        "actions": [
            ("login_attempt",        0.10),
            ("failed_login",         0.08),
            ("port_scan",            0.10),
            ("malware_activity",     0.08),
            ("file_access",          0.10),
            ("data_exfiltration",    0.06),
            ("brute_force",          0.08),
            ("sql_injection",        0.07),
            ("xss_attempt",          0.06),
            ("ddos",                 0.05),
            ("ransomware",           0.04),
            ("privilege_escalation", 0.06),
            ("lateral_movement",     0.06),
            ("c2_communication",     0.05),
            ("dns_tunneling",        0.05),
        ],
    },
}

# ─── Payload Builder ──────────────────────────────────────────────────────────
def build_payload(action, prefer_internal=False):
    """Build a realistic telemetry payload for the given action."""

    # IP selection
    if prefer_internal or random.random() < 0.25:
        ip = random.choice(INTERNAL_IPS)
    else:
        ip = random.choice(EXTERNAL_IPS)

    base = {
        "ip":              ip,
        "action":          action,
        "loginAttempts":   0,
        "portScans":       0,
        "malwareDetected": 0,
        "dataTransferred": 0,
        "requestCount":    random.randint(1, 20),
        "protocol":        random.choice(PROTOCOLS[:4]),
        "port":            0,
        "source":          "simulator",
    }

    # ── Enrich per action ──────────────────────────────────────────────────────
    if action == "login_attempt":
        base["loginAttempts"] = random.randint(1, 8)
        base["port"]          = random.choice([22, 3389, 21])
        base["protocol"]      = "TCP"

    elif action == "failed_login":
        base["loginAttempts"] = random.randint(5, 40)
        base["port"]          = random.choice([22, 3389])
        base["protocol"]      = "TCP"

    elif action == "brute_force":
        base["loginAttempts"] = random.randint(50, 500)
        base["requestCount"]  = random.randint(50, 500)
        base["port"]          = random.choice([22, 3389, 21, 23])
        base["protocol"]      = "TCP"

    elif action == "port_scan":
        base["portScans"]     = random.randint(20, 800)
        base["requestCount"]  = random.randint(20, 2000)
        base["protocol"]      = random.choice(["TCP", "UDP", "ICMP"])
        base["port"]          = 0

    elif action == "malware_activity":
        base["malwareDetected"] = random.randint(1, 10)
        base["port"]            = random.choice(HIGH_RISK_PORTS)
        base["protocol"]        = "TCP"

    elif action == "ransomware":
        base["malwareDetected"] = random.randint(3, 20)
        base["dataTransferred"] = random.randint(10_000_000, 200_000_000)
        base["port"]            = random.choice([445, 3389, 135])
        base["protocol"]        = "TCP"

    elif action == "data_exfiltration":
        base["dataTransferred"] = random.randint(50_000_000, 800_000_000)
        base["port"]            = random.choice([443, 80, 8080])
        base["protocol"]        = "HTTPS"

    elif action == "dns_tunneling":
        base["dataTransferred"] = random.randint(5_000_000, 100_000_000)
        base["port"]            = 53
        base["protocol"]        = "DNS"

    elif action in ("sql_injection", "xss_attempt"):
        base["port"]     = random.choice([80, 443, 8080, 8443])
        base["protocol"] = random.choice(["HTTP", "HTTPS"])

    elif action == "ddos":
        base["portScans"]     = random.randint(500, 10000)
        base["requestCount"]  = random.randint(1000, 50000)
        base["protocol"]      = random.choice(["UDP", "TCP", "ICMP"])

    elif action in ("privilege_escalation", "lateral_movement"):
        base["port"]     = random.choice(HIGH_RISK_PORTS)
        base["protocol"] = "TCP"

    elif action == "c2_communication":
        base["port"]     = random.choice([443, 80, 8443, 4444, 8888])
        base["protocol"] = random.choice(["HTTPS", "TCP"])

    # Fallback port
    if base["port"] == 0:
        base["port"] = random.choice(
            HIGH_RISK_PORTS if random.random() < 0.3
            else COMMON_PORTS if random.random() < 0.5
            else [random.randint(1025, 65535)]
        )

    return base


# ─── Print helpers ────────────────────────────────────────────────────────────
def print_header(scenario_name, scenario, url, interval):
    print("\n" + "═" * 68)
    print(f"  {Fore.CYAN + Style.BRIGHT}Cyber Threat Telemetry Simulator{Style.RESET_ALL}")
    print(f"  Scenario  : {Fore.YELLOW}{scenario_name}{Style.RESET_ALL} — {scenario['description']}")
    print(f"  Target    : {Fore.CYAN}{url}{Style.RESET_ALL}")
    print(f"  Interval  : {interval}s between events")
    print("═" * 68)
    print(
        f"  {'TIME':8s}  {'SEVERITY':9s}  {'IP':18s}  "
        f"{'ACTION':24s}  {'CONF':7s}  {'MS':5s}"
    )
    print("  " + "─" * 66)


def print_event(payload, result, elapsed_ms):
    threat = result.get("threat", {})
    sev    = threat.get("severity", "?")
    conf   = threat.get("confidence", 0)
    color  = SEV_COLOR.get(sev, "")
    ts     = datetime.now().strftime("%H:%M:%S")

    print(
        f"  {Fore.WHITE}{ts}{Style.RESET_ALL}  "
        f"{color}{sev:9s}{Style.RESET_ALL}  "
        f"{Fore.CYAN}{payload['ip']:18s}{Style.RESET_ALL}  "
        f"{Fore.WHITE}{payload['action']:24s}{Style.RESET_ALL}  "
        f"{conf*100:5.1f}%   "
        f"{Fore.WHITE}{elapsed_ms:4.0f}ms{Style.RESET_ALL}"
    )


def print_error(payload, error):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"  {ts}  {SEV_COLOR['ERROR']}{'ERROR':9s}{Style.RESET_ALL}  "
          f"{payload['ip']:18s}  {str(error)[:50]}")


def print_summary(sent, success, fail):
    print("\n" + "═" * 68)
    print(f"  {Fore.CYAN}Simulation complete{Style.RESET_ALL}")
    print(f"  Sent    : {sent}")
    print(f"  Success : {Fore.GREEN}{success}{Style.RESET_ALL}")
    print(f"  Failed  : {Fore.RED}{fail}{Style.RESET_ALL}")
    print("═" * 68 + "\n")


# ─── Modes ────────────────────────────────────────────────────────────────────
def run_continuous(scenario_name, interval_override=None, url=BACKEND_URL):
    scenario   = SCENARIOS[scenario_name]
    interval   = interval_override or scenario["interval"]
    actions    = [a[0] for a in scenario["actions"]]
    weights    = [a[1] for a in scenario["actions"]]
    prefer_int = scenario.get("prefer_internal", False)

    print_header(scenario_name, scenario, url, interval)

    sent = success = fail = 0
    try:
        while True:
            action  = random.choices(actions, weights=weights, k=1)[0]
            payload = build_payload(action, prefer_int)

            t0 = time.perf_counter()
            try:
                resp    = requests.post(url, json=payload, timeout=TIMEOUT)
                elapsed = (time.perf_counter() - t0) * 1000
                sent   += 1
                if resp.status_code in (200, 201):
                    print_event(payload, resp.json(), elapsed)
                    success += 1
                else:
                    print_error(payload, f"HTTP {resp.status_code}")
                    fail += 1
            except requests.exceptions.ConnectionError:
                print(f"\n  {SEV_COLOR['ERROR']}Backend not reachable at {url}{Style.RESET_ALL}")
                print(f"  Start backend first:  cd backend && npm run dev\n")
                time.sleep(6)
                continue
            except requests.exceptions.Timeout:
                print_error(payload, "Request timed out")
                fail += 1

            # Small jitter to feel more realistic
            jitter = random.uniform(-interval * 0.15, interval * 0.15)
            time.sleep(max(0.05, interval + jitter))

    except KeyboardInterrupt:
        print_summary(sent, success, fail)


def run_burst(n, scenario_name, url=BACKEND_URL):
    scenario   = SCENARIOS[scenario_name]
    actions    = [a[0] for a in scenario["actions"]]
    weights    = [a[1] for a in scenario["actions"]]
    prefer_int = scenario.get("prefer_internal", False)

    print(f"\n  {Fore.CYAN}Burst mode{Style.RESET_ALL} — sending {n} events (scenario: {scenario_name})\n")
    print(f"  {'TIME':8s}  {'SEVERITY':9s}  {'IP':18s}  {'ACTION':24s}  {'CONF':7s}")
    print("  " + "─" * 66)

    sent = success = fail = 0
    for _ in range(n):
        action  = random.choices(actions, weights=weights, k=1)[0]
        payload = build_payload(action, prefer_int)
        try:
            t0   = time.perf_counter()
            resp = requests.post(url, json=payload, timeout=TIMEOUT)
            ms   = (time.perf_counter() - t0) * 1000
            sent += 1
            if resp.status_code in (200, 201):
                print_event(payload, resp.json(), ms)
                success += 1
            else:
                print_error(payload, f"HTTP {resp.status_code}")
                fail += 1
        except Exception as e:
            print_error(payload, str(e))
            fail += 1
        time.sleep(0.08)   # small gap so backend isn't overwhelmed

    print_summary(sent, success, fail)


def run_scenario_chain(url=BACKEND_URL):
    """
    Runs a scripted multi-phase attack chain:
    recon → brute-force → malware → lateral movement → exfiltration
    """
    chain = [
        ("port_scan",            "port_scan",            10, 0.2),
        ("reconnaissance",       "port_scan",            5,  0.3),
        ("credential_attack",    "brute_force",          15, 0.4),
        ("initial_compromise",   "malware_activity",     5,  0.5),
        ("privilege_escalation", "privilege_escalation", 5,  0.6),
        ("lateral_movement",     "lateral_movement",     8,  0.7),
        ("c2_setup",             "c2_communication",     6,  0.8),
        ("data_staging",         "file_access",          10, 0.2),
        ("exfiltration",         "data_exfiltration",    5,  1.0),
        ("persistence",          "ransomware",           3,  1.2),
    ]

    print("\n" + "═" * 68)
    print(f"  {Fore.MAGENTA + Style.BRIGHT}APT KILL CHAIN SIMULATION{Style.RESET_ALL}")
    print(f"  Simulating a full multi-stage attack lifecycle")
    print("═" * 68 + "\n")

    for phase_name, action, count, interval in chain:
        print(f"  {Fore.YELLOW}▶ Phase: {phase_name.upper().replace('_',' ')}{Style.RESET_ALL}")
        for _ in range(count):
            payload = build_payload(action)
            try:
                t0   = time.perf_counter()
                resp = requests.post(url, json=payload, timeout=TIMEOUT)
                ms   = (time.perf_counter() - t0) * 1000
                if resp.status_code in (200, 201):
                    print_event(payload, resp.json(), ms)
            except Exception as e:
                print_error(payload, str(e))
            time.sleep(interval)
        print()

    print(f"  {Fore.GREEN}Kill chain simulation complete.{Style.RESET_ALL}\n")


# ─── CLI ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Cyber Threat Telemetry Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python telemetry_simulator.py
  python telemetry_simulator.py --scenario ddos
  python telemetry_simulator.py --scenario apt --interval 5
  python telemetry_simulator.py --burst 100 --scenario mixed
  python telemetry_simulator.py --killchain
  python telemetry_simulator.py --list
        """
    )
    parser.add_argument("--scenario",  default="normal",
                        choices=list(SCENARIOS.keys()),
                        help="Attack scenario (default: normal)")
    parser.add_argument("--burst",     type=int, default=0,
                        help="Send N events then exit (0 = continuous)")
    parser.add_argument("--interval",  type=float, default=None,
                        help="Override seconds between events")
    parser.add_argument("--url",       default=BACKEND_URL,
                        help=f"Backend URL (default: {BACKEND_URL})")
    parser.add_argument("--killchain", action="store_true",
                        help="Run full APT kill chain simulation")
    parser.add_argument("--list",      action="store_true",
                        help="List all available scenarios and exit")

    args = parser.parse_args()

    if args.list:
        print(f"\n  {Fore.CYAN}Available Scenarios:{Style.RESET_ALL}\n")
        for name, sc in SCENARIOS.items():
            print(f"  {Fore.YELLOW}{name:12s}{Style.RESET_ALL}  {sc['description']}")
            print(f"  {'':12s}  interval={sc['interval']}s  "
                  f"actions={len(sc['actions'])}")
            print()
        return

    if args.killchain:
        run_scenario_chain(url=args.url)
        return

    if args.burst > 0:
        run_burst(args.burst, args.scenario, url=args.url)
    else:
        run_continuous(args.scenario, args.interval, url=args.url)


if __name__ == "__main__":
    main()