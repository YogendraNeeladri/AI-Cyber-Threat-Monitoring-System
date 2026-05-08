"""
Synthetic Training Data Generator
Produces realistic, labeled telemetry samples for model training.
Carefully calibrated distributions to reflect real-world threat patterns.
"""

import numpy as np
import pandas as pd
from utils.logger import get_logger

logger = get_logger("data_generator")

# Severity label encoding
SEVERITY_LABELS = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
LABEL_TO_SEVERITY = {v: k for k, v in SEVERITY_LABELS.items()}

# Action → default severity distribution
ACTION_SEVERITY_DIST = {
    # action: [(severity, weight), ...]
    "login_attempt":        [("LOW", 0.75), ("MEDIUM", 0.20), ("HIGH", 0.05)],
    "failed_login":         [("LOW", 0.30), ("MEDIUM", 0.50), ("HIGH", 0.20)],
    "port_scan":            [("MEDIUM", 0.25), ("HIGH", 0.60), ("CRITICAL", 0.15)],
    "malware_activity":     [("HIGH", 0.35), ("CRITICAL", 0.65)],
    "file_access":          [("LOW", 0.65), ("MEDIUM", 0.30), ("HIGH", 0.05)],
    "data_exfiltration":    [("HIGH", 0.20), ("CRITICAL", 0.80)],
    "brute_force":          [("MEDIUM", 0.20), ("HIGH", 0.65), ("CRITICAL", 0.15)],
    "sql_injection":        [("HIGH", 0.45), ("CRITICAL", 0.55)],
    "xss_attempt":          [("MEDIUM", 0.40), ("HIGH", 0.60)],
    "ddos":                 [("HIGH", 0.20), ("CRITICAL", 0.80)],
    "ransomware":           [("CRITICAL", 1.00)],
    "privilege_escalation": [("HIGH", 0.30), ("CRITICAL", 0.70)],
    "lateral_movement":     [("HIGH", 0.40), ("CRITICAL", 0.60)],
    "c2_communication":     [("HIGH", 0.25), ("CRITICAL", 0.75)],
    "dns_tunneling":        [("HIGH", 0.50), ("CRITICAL", 0.50)],
}

ACTIONS = list(ACTION_SEVERITY_DIST.keys())

# Sample IPs per category
EXTERNAL_IPS = [
    "185.220.101.45", "45.141.84.120", "91.108.4.100", "77.88.55.88",
    "198.51.100.23", "203.0.113.50", "104.21.45.67", "156.89.12.34",
    "62.173.145.10", "178.73.215.94", "5.188.86.172", "149.28.54.89",
    "103.75.190.12", "121.4.120.50",  "167.94.138.30", "80.82.77.33",
]
INTERNAL_IPS = [
    "192.168.1.10", "192.168.1.55", "192.168.0.100", "10.0.0.20",
    "10.0.1.50",    "172.16.0.10",  "172.31.255.50", "127.0.0.1",
]

PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"]
HIGH_RISK_PORTS = [22, 23, 3389, 445, 135, 1433, 3306, 5432, 6379, 27017]
COMMON_PORTS = [80, 443, 8080, 8443, 8888, 9090, 5000, 3000]


def _sample_severity(action):
    dist = ACTION_SEVERITY_DIST[action]
    severities = [d[0] for d in dist]
    weights = [d[1] for d in dist]
    return np.random.choice(severities, p=weights)


def _generate_telemetry_for(action, severity):
    """Generate realistic telemetry values based on action + severity."""
    rng = np.random

    base_multiplier = {"LOW": 0.5, "MEDIUM": 1.0, "HIGH": 2.5, "CRITICAL": 6.0}[severity]

    t = {
        "loginAttempts": 0,
        "portScans": 0,
        "malwareDetected": 0,
        "dataTransferred": 0,
        "requestCount": max(1, int(rng.exponential(10 * base_multiplier))),
        "protocol": rng.choice(PROTOCOLS, p=[0.35, 0.20, 0.10, 0.15, 0.15, 0.05]),
        "port": 0,
    }

    if action in ("login_attempt", "failed_login", "brute_force"):
        if severity == "LOW":
            t["loginAttempts"] = rng.randint(1, 5)
        elif severity == "MEDIUM":
            t["loginAttempts"] = rng.randint(5, 25)
        elif severity == "HIGH":
            t["loginAttempts"] = rng.randint(20, 100)
        else:
            t["loginAttempts"] = rng.randint(100, 500)

    if action in ("port_scan", "ddos", "lateral_movement"):
        if severity == "MEDIUM":
            t["portScans"] = rng.randint(5, 30)
        elif severity == "HIGH":
            t["portScans"] = rng.randint(25, 200)
        else:
            t["portScans"] = rng.randint(100, 1000)
        t["protocol"] = rng.choice(["TCP", "UDP", "ICMP"])

    if action in ("malware_activity", "ransomware", "c2_communication"):
        t["malwareDetected"] = rng.randint(1, 15 if severity == "CRITICAL" else 5)
        t["protocol"] = rng.choice(["TCP", "HTTPS"])

    if action in ("data_exfiltration", "dns_tunneling"):
        if severity == "HIGH":
            t["dataTransferred"] = int(rng.uniform(5_000_000, 50_000_000))
        else:
            t["dataTransferred"] = int(rng.uniform(50_000_000, 500_000_000))

    if action in ("sql_injection", "xss_attempt"):
        t["protocol"] = "HTTP" if rng.random() < 0.5 else "HTTPS"
        t["port"] = rng.choice([80, 443, 8080, 8443])

    if action in ("privilege_escalation", "lateral_movement"):
        t["port"] = rng.choice(HIGH_RISK_PORTS)
        t["protocol"] = "TCP"

    # Port assignment if not set
    if t["port"] == 0:
        if rng.random() < 0.3:
            t["port"] = rng.choice(HIGH_RISK_PORTS)
        elif rng.random() < 0.5:
            t["port"] = rng.choice(COMMON_PORTS)
        else:
            t["port"] = rng.randint(1024, 65535)

    return t


def generate_dataset(n_samples=15000, random_state=42):
    """
    Generate a labeled dataset of telemetry events.
    Returns (X_raw list, y_labels list, severity_labels list)
    """
    np.random.seed(random_state)
    logger.info(f"Generating {n_samples} synthetic training samples...")

    # Action distribution — weighted toward realistic proportions
    action_weights = [
        0.12, 0.10, 0.09, 0.07, 0.10, 0.05, 0.08,  # login, failed, port_scan, malware, file, exfil, brute
        0.06, 0.06, 0.04, 0.03, 0.04, 0.04, 0.06, 0.06,  # sql, xss, ddos, ransomware, priv, lateral, c2, dns
    ]
    action_weights = np.array(action_weights) / sum(action_weights)

    samples = []
    for _ in range(n_samples):
        action = np.random.choice(ACTIONS, p=action_weights)
        severity = _sample_severity(action)
        telemetry = _generate_telemetry_for(action, severity)

        # Assign IP: internal more common for LOW
        if severity == "LOW" and np.random.random() < 0.6:
            ip = np.random.choice(INTERNAL_IPS)
        else:
            ip = np.random.choice(EXTERNAL_IPS if np.random.random() < 0.75 else INTERNAL_IPS)

        samples.append({
            "ip": ip,
            "action": action,
            "severity": severity,
            "label": SEVERITY_LABELS[severity],
            "threat": severity in ("MEDIUM", "HIGH", "CRITICAL"),
            "telemetry": telemetry,
        })

    logger.info(f"Dataset generated. Distribution:")
    for s in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        count = sum(1 for x in samples if x["severity"] == s)
        logger.info(f"  {s}: {count} ({100*count/n_samples:.1f}%)")

    return samples
