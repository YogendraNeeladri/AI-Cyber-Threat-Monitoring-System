"""
Feature Engineering Pipeline
Converts raw telemetry payloads into numerical feature vectors
for the ML classifier.
"""

import numpy as np
import ipaddress
from utils.logger import get_logger

logger = get_logger("feature_engineer")

# ─── Action Encodings ─────────────────────────────────────────────────────────
ACTION_MAP = {
    "login_attempt":        0,
    "failed_login":         1,
    "port_scan":            2,
    "malware_activity":     3,
    "file_access":          4,
    "data_exfiltration":    5,
    "brute_force":          6,
    "sql_injection":        7,
    "xss_attempt":          8,
    "ddos":                 9,
    "ransomware":           10,
    "privilege_escalation": 11,
    "lateral_movement":     12,
    "c2_communication":     13,
    "dns_tunneling":        14,
}

# Action base risk scores (0–1)
ACTION_RISK = {
    "login_attempt":        0.10,
    "failed_login":         0.35,
    "port_scan":            0.65,
    "malware_activity":     0.92,
    "file_access":          0.15,
    "data_exfiltration":    0.95,
    "brute_force":          0.75,
    "sql_injection":        0.80,
    "xss_attempt":          0.70,
    "ddos":                 0.90,
    "ransomware":           0.98,
    "privilege_escalation": 0.88,
    "lateral_movement":     0.82,
    "c2_communication":     0.94,
    "dns_tunneling":        0.85,
}

FEATURE_NAMES = [
    "action_encoded",
    "action_risk_score",
    "is_private_ip",
    "ip_first_octet",
    "ip_last_octet",
    "ip_is_loopback",
    "ip_is_multicast",
    "login_attempts",
    "port_scans",
    "malware_detected",
    "data_transferred_kb",
    "request_count",
    "port_normalized",
    "is_well_known_port",
    "is_high_risk_port",
    "protocol_encoded",
    "login_burst_flag",
    "port_scan_burst_flag",
    "malware_flag",
    "data_exfil_flag",
    "composite_risk_score",
    "anomaly_score",
]


class FeatureEngineer:
    """
    Transforms raw telemetry dictionaries into fixed-length
    numerical feature vectors suitable for sklearn classifiers.
    """

    def __init__(self):
        self.feature_names = FEATURE_NAMES
        self.n_features = len(FEATURE_NAMES)
        logger.info(f"FeatureEngineer initialized with {self.n_features} features")

    # ─── IP Analysis ──────────────────────────────────────────────────────────
    def _parse_ip(self, ip_str):
        try:
            ip = ipaddress.ip_address(str(ip_str).strip())
            return {
                "is_private":    int(ip.is_private),
                "is_loopback":   int(ip.is_loopback),
                "is_multicast":  int(ip.is_multicast),
                "first_octet":   int(str(ip).split(".")[0]) / 255.0 if ip.version == 4 else 0.5,
                "last_octet":    int(str(ip).split(".")[-1]) / 255.0 if ip.version == 4 else 0.5,
            }
        except Exception:
            return {
                "is_private": 0, "is_loopback": 0, "is_multicast": 0,
                "first_octet": 0.5, "last_octet": 0.5,
            }

    # ─── Port Analysis ────────────────────────────────────────────────────────
    def _analyze_port(self, port):
        port = int(port or 0)
        well_known = int(port < 1024)
        high_risk_ports = {22, 23, 3389, 445, 135, 139, 1433, 3306, 5432, 6379, 27017}
        is_high_risk = int(port in high_risk_ports)
        normalized = port / 65535.0 if port > 0 else 0.0
        return normalized, well_known, is_high_risk

    # ─── Protocol Encoding ────────────────────────────────────────────────────
    def _encode_protocol(self, protocol):
        protos = {"TCP": 0.2, "UDP": 0.4, "ICMP": 0.6, "HTTP": 0.3, "HTTPS": 0.25, "DNS": 0.5}
        return protos.get(str(protocol).upper(), 0.1)

    # ─── Burst Detection ──────────────────────────────────────────────────────
    def _detect_bursts(self, telemetry):
        login_burst = int(telemetry.get("loginAttempts", 0) > 10)
        port_scan_burst = int(telemetry.get("portScans", 0) > 20)
        malware_flag = int(telemetry.get("malwareDetected", 0) > 0)
        data_exfil_flag = int(telemetry.get("dataTransferred", 0) > 10_000_000)  # 10MB
        return login_burst, port_scan_burst, malware_flag, data_exfil_flag

    # ─── Composite Risk Score ─────────────────────────────────────────────────
    def _composite_risk(self, action, telemetry, ip_info):
        base = ACTION_RISK.get(action, 0.1)

        # Amplifiers
        amplifier = 1.0
        if telemetry.get("malwareDetected", 0) > 0:
            amplifier *= 1.5
        if telemetry.get("loginAttempts", 0) > 20:
            amplifier *= 1.3
        if telemetry.get("portScans", 0) > 50:
            amplifier *= 1.4
        if telemetry.get("dataTransferred", 0) > 50_000_000:
            amplifier *= 1.6
        if not ip_info["is_private"]:
            amplifier *= 1.1  # external IPs slightly riskier

        return min(1.0, base * amplifier)

    # ─── Anomaly Score ────────────────────────────────────────────────────────
    def _anomaly_score(self, action, telemetry):
        """Simple heuristic anomaly score based on unusual value combinations."""
        score = 0.0
        t = telemetry

        # High request count for low-risk action
        if action in ["login_attempt", "file_access"] and t.get("requestCount", 0) > 100:
            score += 0.3

        # Port scan + malware combo
        if t.get("portScans", 0) > 5 and t.get("malwareDetected", 0) > 0:
            score += 0.4

        # Huge data transfer
        if t.get("dataTransferred", 0) > 100_000_000:
            score += 0.35

        # Many login failures
        if action == "failed_login" and t.get("loginAttempts", 0) > 30:
            score += 0.4

        return min(1.0, score)

    # ─── Main Transform ───────────────────────────────────────────────────────
    def transform(self, telemetry_dict):
        """
        Convert a raw telemetry dict into a numpy feature vector.
        Returns: np.ndarray of shape (1, n_features)
        """
        ip = telemetry_dict.get("ip", "0.0.0.0")
        action = telemetry_dict.get("action", "login_attempt")
        t = telemetry_dict.get("telemetry", {}) or {}

        # Fallback for flat payloads (action + top-level fields)
        if not t:
            t = {
                "loginAttempts":   telemetry_dict.get("loginAttempts", 0),
                "portScans":       telemetry_dict.get("portScans", 0),
                "malwareDetected": telemetry_dict.get("malwareDetected", 0),
                "dataTransferred": telemetry_dict.get("dataTransferred", 0),
                "requestCount":    telemetry_dict.get("requestCount", 1),
                "protocol":        telemetry_dict.get("protocol", "TCP"),
                "port":            telemetry_dict.get("port", 0),
            }

        ip_info = self._parse_ip(ip)
        port_norm, well_known, high_risk_port = self._analyze_port(t.get("port", 0))
        login_burst, scan_burst, malware_flag, exfil_flag = self._detect_bursts(t)
        composite = self._composite_risk(action, t, ip_info)
        anomaly = self._anomaly_score(action, t)

        features = np.array([
            ACTION_MAP.get(action, 0),                              # action_encoded
            ACTION_RISK.get(action, 0.1),                           # action_risk_score
            ip_info["is_private"],                                  # is_private_ip
            ip_info["first_octet"],                                 # ip_first_octet
            ip_info["last_octet"],                                  # ip_last_octet
            ip_info["is_loopback"],                                 # ip_is_loopback
            ip_info["is_multicast"],                                # ip_is_multicast
            min(t.get("loginAttempts", 0), 1000) / 1000.0,         # login_attempts (normalized)
            min(t.get("portScans", 0), 1000) / 1000.0,             # port_scans (normalized)
            min(t.get("malwareDetected", 0), 100) / 100.0,         # malware_detected (normalized)
            min(t.get("dataTransferred", 0), 1e9) / 1e9,           # data_transferred_kb
            min(t.get("requestCount", 1), 10000) / 10000.0,        # request_count
            port_norm,                                              # port_normalized
            well_known,                                             # is_well_known_port
            high_risk_port,                                         # is_high_risk_port
            self._encode_protocol(t.get("protocol", "TCP")),       # protocol_encoded
            login_burst,                                            # login_burst_flag
            scan_burst,                                             # port_scan_burst_flag
            malware_flag,                                           # malware_flag
            exfil_flag,                                             # data_exfil_flag
            composite,                                              # composite_risk_score
            anomaly,                                                # anomaly_score
        ], dtype=np.float32)

        return features.reshape(1, -1)

    def transform_batch(self, telemetry_list):
        """Transform a list of telemetry dicts into a 2D feature matrix."""
        return np.vstack([self.transform(t) for t in telemetry_list])

    def get_feature_names(self):
        return self.feature_names
