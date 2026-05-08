"""
Synthetic cybersecurity telemetry dataset generator.
Produces a realistic, class-balanced dataset for training the threat classifier.
Each row represents one security event with numeric features extracted from raw telemetry.
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import random
import os

random.seed(42)
np.random.seed(42)

# ─── Action type encoding ─────────────────────────────────────────────────────
ACTION_MAP = {
    'login_attempt':        0,
    'failed_login':         1,
    'port_scan':            2,
    'malware_activity':     3,
    'file_access':          4,
    'data_exfiltration':    5,
    'brute_force':          6,
    'sql_injection':        7,
    'xss_attempt':          8,
    'ddos':                 9,
    'ransomware':           10,
    'privilege_escalation': 11,
    'lateral_movement':     12,
    'c2_communication':     13,
    'dns_tunneling':        14,
}

# ─── Severity encoding ────────────────────────────────────────────────────────
SEVERITY_MAP     = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
SEVERITY_REVERSE = {v: k for k, v in SEVERITY_MAP.items()}

# ─── Protocol encoding ────────────────────────────────────────────────────────
PROTOCOL_MAP = {'TCP': 0, 'UDP': 1, 'ICMP': 2, 'HTTP': 3, 'HTTPS': 4, 'DNS': 5}

# ─── Feature profiles per action ──────────────────────────────────────────────
# Each profile defines (severity_weights, feature_ranges)
# severity_weights = [LOW, MEDIUM, HIGH, CRITICAL]
PROFILES = {
    'login_attempt': {
        'severity_weights': [0.70, 0.20, 0.08, 0.02],
        'login_attempts':   (1, 5),
        'port_scans':       (0, 2),
        'malware_detected': (0, 0),
        'data_transferred': (100, 5000),
        'request_count':    (1, 20),
        'port':             [22, 80, 443, 3389, 8080],
        'protocol':         ['TCP', 'HTTPS'],
    },
    'failed_login': {
        'severity_weights': [0.30, 0.40, 0.25, 0.05],
        'login_attempts':   (3, 50),
        'port_scans':       (0, 5),
        'malware_detected': (0, 0),
        'data_transferred': (50, 2000),
        'request_count':    (3, 80),
        'port':             [22, 3389, 5900, 21],
        'protocol':         ['TCP'],
    },
    'port_scan': {
        'severity_weights': [0.05, 0.20, 0.60, 0.15],
        'login_attempts':   (0, 3),
        'port_scans':       (20, 500),
        'malware_detected': (0, 1),
        'data_transferred': (500, 10000),
        'request_count':    (50, 1000),
        'port':             list(range(1, 1024)),
        'protocol':         ['TCP', 'UDP', 'ICMP'],
    },
    'malware_activity': {
        'severity_weights': [0.02, 0.08, 0.50, 0.40],
        'login_attempts':   (0, 5),
        'port_scans':       (5, 100),
        'malware_detected': (1, 10),
        'data_transferred': (1000, 500000),
        'request_count':    (10, 200),
        'port':             [443, 80, 8443, 4444, 1337],
        'protocol':         ['TCP', 'HTTPS'],
    },
    'file_access': {
        'severity_weights': [0.60, 0.25, 0.10, 0.05],
        'login_attempts':   (0, 2),
        'port_scans':       (0, 0),
        'malware_detected': (0, 1),
        'data_transferred': (100, 100000),
        'request_count':    (1, 30),
        'port':             [445, 139, 21, 22],
        'protocol':         ['TCP'],
    },
    'data_exfiltration': {
        'severity_weights': [0.02, 0.08, 0.35, 0.55],
        'login_attempts':   (0, 5),
        'port_scans':       (0, 20),
        'malware_detected': (1, 5),
        'data_transferred': (500000, 50000000),
        'request_count':    (5, 100),
        'port':             [443, 80, 53, 21],
        'protocol':         ['TCP', 'HTTPS', 'DNS'],
    },
    'brute_force': {
        'severity_weights': [0.05, 0.25, 0.50, 0.20],
        'login_attempts':   (50, 5000),
        'port_scans':       (0, 10),
        'malware_detected': (0, 0),
        'data_transferred': (100, 5000),
        'request_count':    (50, 5000),
        'port':             [22, 3389, 21, 5900, 25],
        'protocol':         ['TCP'],
    },
    'sql_injection': {
        'severity_weights': [0.05, 0.20, 0.50, 0.25],
        'login_attempts':   (1, 20),
        'port_scans':       (0, 5),
        'malware_detected': (0, 2),
        'data_transferred': (200, 50000),
        'request_count':    (5, 500),
        'port':             [80, 443, 3306, 5432, 8080],
        'protocol':         ['TCP', 'HTTP', 'HTTPS'],
    },
    'xss_attempt': {
        'severity_weights': [0.10, 0.40, 0.35, 0.15],
        'login_attempts':   (0, 5),
        'port_scans':       (0, 3),
        'malware_detected': (0, 1),
        'data_transferred': (100, 20000),
        'request_count':    (1, 100),
        'port':             [80, 443, 8080],
        'protocol':         ['HTTP', 'HTTPS'],
    },
    'ddos': {
        'severity_weights': [0.01, 0.04, 0.25, 0.70],
        'login_attempts':   (0, 10),
        'port_scans':       (100, 2000),
        'malware_detected': (0, 3),
        'data_transferred': (10000, 10000000),
        'request_count':    (1000, 100000),
        'port':             [80, 443, 53],
        'protocol':         ['TCP', 'UDP'],
    },
    'ransomware': {
        'severity_weights': [0.00, 0.02, 0.18, 0.80],
        'login_attempts':   (0, 10),
        'port_scans':       (5, 50),
        'malware_detected': (3, 20),
        'data_transferred': (50000, 5000000),
        'request_count':    (10, 500),
        'port':             [445, 3389, 443, 4444],
        'protocol':         ['TCP'],
    },
    'privilege_escalation': {
        'severity_weights': [0.02, 0.08, 0.45, 0.45],
        'login_attempts':   (1, 20),
        'port_scans':       (0, 20),
        'malware_detected': (1, 8),
        'data_transferred': (1000, 100000),
        'request_count':    (5, 100),
        'port':             [22, 3389, 445, 139],
        'protocol':         ['TCP'],
    },
    'lateral_movement': {
        'severity_weights': [0.02, 0.10, 0.48, 0.40],
        'login_attempts':   (2, 50),
        'port_scans':       (10, 200),
        'malware_detected': (1, 5),
        'data_transferred': (5000, 500000),
        'request_count':    (20, 500),
        'port':             [445, 135, 139, 22, 3389],
        'protocol':         ['TCP'],
    },
    'c2_communication': {
        'severity_weights': [0.01, 0.04, 0.40, 0.55],
        'login_attempts':   (0, 5),
        'port_scans':       (0, 30),
        'malware_detected': (2, 15),
        'data_transferred': (1000, 200000),
        'request_count':    (10, 300),
        'port':             [443, 80, 8080, 4444, 1337, 6666],
        'protocol':         ['TCP', 'HTTPS'],
    },
    'dns_tunneling': {
        'severity_weights': [0.02, 0.08, 0.45, 0.45],
        'login_attempts':   (0, 3),
        'port_scans':       (0, 10),
        'malware_detected': (1, 5),
        'data_transferred': (500, 100000),
        'request_count':    (100, 10000),
        'port':             [53],
        'protocol':         ['DNS', 'UDP'],
    },
}

def is_private_ip(ip: str) -> int:
    parts = ip.split('.')
    if len(parts) != 4:
        return 0
    try:
        first, second = int(parts[0]), int(parts[1])
        return int(
            first == 10 or
            (first == 172 and 16 <= second <= 31) or
            (first == 192 and second == 168) or
            first == 127
        )
    except ValueError:
        return 0

def random_ip(is_private: bool = False) -> str:
    if is_private:
        return f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
    # Public IPs — avoid reserved ranges
    while True:
        first = random.choice([45, 77, 91, 104, 185, 198, 203, 5, 31, 46,
                                62, 78, 82, 89, 93, 95, 109, 176, 213, 217])
        ip = f"{first}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        return ip

def generate_sample(action: str, n: int = 1) -> list:
    profile = PROFILES[action]
    rows = []
    action_code = ACTION_MAP[action]

    for _ in range(n):
        severity_idx = np.random.choice(4, p=profile['severity_weights'])
        severity = SEVERITY_REVERSE[severity_idx]

        use_private = random.random() < 0.2
        ip = random_ip(is_private=use_private)

        lo, hi = profile['login_attempts']
        login_attempts = random.randint(lo, hi)
        # Scale up for HIGH/CRITICAL
        if severity in ('HIGH', 'CRITICAL'):
            login_attempts = int(login_attempts * random.uniform(1.5, 4.0))

        lo, hi = profile['port_scans']
        port_scans = random.randint(lo, hi)
        if severity in ('HIGH', 'CRITICAL'):
            port_scans = int(port_scans * random.uniform(1.5, 5.0))

        lo, hi = profile['malware_detected']
        malware_detected = random.randint(lo, hi)
        if severity == 'CRITICAL':
            malware_detected = max(malware_detected, random.randint(2, 20))

        lo, hi = profile['data_transferred']
        data_transferred = random.randint(lo, hi)
        if severity in ('HIGH', 'CRITICAL'):
            data_transferred = int(data_transferred * random.uniform(2.0, 10.0))

        lo, hi = profile['request_count']
        request_count = random.randint(lo, hi)

        port = random.choice(profile['port'])
        protocol = random.choice(profile['protocol'])
        hour_of_day = random.randint(0, 23)
        # Attacks more likely at night
        if severity in ('HIGH', 'CRITICAL') and random.random() < 0.6:
            hour_of_day = random.choice([0,1,2,3,22,23])

        is_night = int(hour_of_day < 6 or hour_of_day >= 22)
        is_business_hours = int(8 <= hour_of_day <= 18)
        is_private = is_private_ip(ip)

        # Derived risk features
        login_rate_risk = min(1.0, login_attempts / 100.0)
        scan_rate_risk  = min(1.0, port_scans / 500.0)
        data_risk       = min(1.0, data_transferred / 1_000_000.0)
        malware_risk    = min(1.0, malware_detected / 10.0)

        rows.append({
            'action':           action_code,
            'login_attempts':   login_attempts,
            'port_scans':       port_scans,
            'malware_detected': malware_detected,
            'data_transferred': data_transferred,
            'request_count':    request_count,
            'port':             port,
            'protocol':         PROTOCOL_MAP.get(protocol, 0),
            'is_private_ip':    is_private,
            'hour_of_day':      hour_of_day,
            'is_night':         is_night,
            'is_business_hours':is_business_hours,
            'login_rate_risk':  round(login_rate_risk, 4),
            'scan_rate_risk':   round(scan_rate_risk, 4),
            'data_risk':        round(data_risk, 4),
            'malware_risk':     round(malware_risk, 4),
            'combined_risk':    round((login_rate_risk + scan_rate_risk + data_risk + malware_risk) / 4, 4),
            'severity':         severity,
            'severity_code':    severity_idx,
            'threat':           int(severity in ('MEDIUM', 'HIGH', 'CRITICAL')),
        })

    return rows

def generate_dataset(samples_per_action: int = 800) -> pd.DataFrame:
    all_rows = []
    for action in PROFILES:
        rows = generate_sample(action, n=samples_per_action)
        all_rows.extend(rows)
        print(f"  {action:<25} {len(rows)} samples")

    df = pd.DataFrame(all_rows)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"\nTotal samples: {len(df)}")
    print("\nSeverity distribution:")
    print(df['severity'].value_counts())
    print("\nThreat distribution:")
    print(df['threat'].value_counts())
    return df

FEATURE_COLUMNS = [
    'action', 'login_attempts', 'port_scans', 'malware_detected',
    'data_transferred', 'request_count', 'port', 'protocol',
    'is_private_ip', 'hour_of_day', 'is_night', 'is_business_hours',
    'login_rate_risk', 'scan_rate_risk', 'data_risk', 'malware_risk',
    'combined_risk',
]

if __name__ == '__main__':
    print("Generating cybersecurity training dataset...")
    df = generate_dataset(samples_per_action=1000)
    out_path = os.path.join(os.path.dirname(__file__), 'training_data.csv')
    df.to_csv(out_path, index=False)
    print(f"\nDataset saved to: {out_path}")
