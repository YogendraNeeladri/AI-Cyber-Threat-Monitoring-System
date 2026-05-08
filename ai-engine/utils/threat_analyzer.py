"""
Threat Analyzer
Orchestrates the full analysis pipeline:
feature engineering → ML prediction → result enrichment → session tracking
"""

import time
import threading
from collections import defaultdict, deque
from datetime import datetime
from utils.logger import get_logger

logger = get_logger("threat_analyzer")

SEVERITY_THREAT_MAP = {
    "LOW":      False,
    "MEDIUM":   True,
    "HIGH":     True,
    "CRITICAL": True,
}

SEVERITY_RECOMMENDATIONS = {
    "LOW": [
        "Log and monitor this activity.",
        "No immediate action required.",
        "Review if pattern repeats within 1 hour.",
    ],
    "MEDIUM": [
        "Investigate the source IP immediately.",
        "Check for related activity from the same IP.",
        "Consider temporary rate-limiting.",
        "Alert the on-call analyst.",
    ],
    "HIGH": [
        "Block the source IP at the firewall.",
        "Isolate affected systems if malware is involved.",
        "Escalate to security team immediately.",
        "Preserve logs for forensic analysis.",
        "Check for lateral movement to adjacent hosts.",
    ],
    "CRITICAL": [
        "IMMEDIATE response required — escalate to CISO.",
        "Isolate all affected network segments.",
        "Initiate incident response protocol.",
        "Preserve all logs and disk images.",
        "Notify stakeholders and legal team if data exfiltration occurred.",
        "Engage external threat intelligence if needed.",
    ],
}


class ThreatAnalyzer:
    def __init__(self, model_manager, feature_engineer):
        self.model_manager = model_manager
        self.feature_engineer = feature_engineer
        self._lock = threading.Lock()

        # Session statistics
        self._session_start = time.time()
        self._stats = {
            "total_analyzed": 0,
            "threats_detected": 0,
            "by_severity": defaultdict(int),
            "by_action": defaultdict(int),
            "avg_confidence": 0.0,
            "confidence_sum": 0.0,
            "avg_latency_ms": 0.0,
            "latency_sum": 0.0,
            "recent_threats": deque(maxlen=100),
        }

    # ─── Main Analysis ────────────────────────────────────────────────────────
    def analyze(self, telemetry_dict):
        """
        Full pipeline: features → predict → enrich → track
        Returns a rich result dict.
        """
        t0 = time.perf_counter()

        # Feature engineering
        features = self.feature_engineer.transform(telemetry_dict)

        # ML prediction
        prediction = self.model_manager.predict(features)

        severity = prediction["severity"]
        confidence = prediction["confidence"]
        is_threat = SEVERITY_THREAT_MAP.get(severity, False)

        # Build result
        result = {
            "severity":        severity,
            "threat":          is_threat,
            "confidence":      confidence,
            "model":           self.model_manager.metadata.get("model_name", "EnsembleVotingClassifier"),
            "model_version":   self.model_manager.metadata.get("version", "1.0.0"),
            "probabilities":   prediction["probabilities"],
            "action":          telemetry_dict.get("action"),
            "ip":              telemetry_dict.get("ip"),
            "recommendations": SEVERITY_RECOMMENDATIONS.get(severity, []),
            "analyzed_at":     datetime.utcnow().isoformat(),
            "features": {
                "composite_risk":  round(float(features[0, 20]), 4),
                "anomaly_score":   round(float(features[0, 21]), 4),
                "action_risk":     round(float(features[0, 1]),  4),
                "is_external_ip":  int(features[0, 2]) == 0,
                "login_burst":     int(features[0, 16]) == 1,
                "port_scan_burst": int(features[0, 17]) == 1,
                "malware_flag":    int(features[0, 18]) == 1,
                "data_exfil_flag": int(features[0, 19]) == 1,
            },
        }

        latency_ms = (time.perf_counter() - t0) * 1000
        result["latency_ms"] = round(latency_ms, 3)

        # Update session stats
        self._update_stats(result, latency_ms)

        return result

    # ─── Explanation ──────────────────────────────────────────────────────────
    def explain(self, telemetry_dict):
        """
        Return a human-readable explanation of why a particular
        severity was assigned, with feature contribution breakdown.
        """
        features = self.feature_engineer.transform(telemetry_dict)
        prediction = self.model_manager.predict(features)
        feature_names = self.feature_engineer.get_feature_names()

        # Get feature importances from the RF inside the ensemble
        try:
            rf = self.model_manager.pipeline.named_steps["classifier"].estimators_[0]
            importances = rf.feature_importances_
            feature_impact = [
                {
                    "feature": name,
                    "value": round(float(features[0, i]), 4),
                    "importance": round(float(importances[i]), 4),
                    "contribution": round(float(features[0, i] * importances[i]), 4),
                }
                for i, name in enumerate(feature_names)
            ]
            feature_impact.sort(key=lambda x: abs(x["contribution"]), reverse=True)
            top_contributors = feature_impact[:8]
        except Exception as e:
            top_contributors = []

        return {
            "severity":          prediction["severity"],
            "confidence":        prediction["confidence"],
            "probabilities":     prediction["probabilities"],
            "top_contributors":  top_contributors,
            "recommendations":   SEVERITY_RECOMMENDATIONS.get(prediction["severity"], []),
            "summary": (
                f"This event was classified as {prediction['severity']} "
                f"with {prediction['confidence']*100:.1f}% confidence. "
                f"The action '{telemetry_dict.get('action')}' carries high inherent risk "
                f"and the telemetry values amplified the threat score."
            ),
        }

    # ─── Session Stats ────────────────────────────────────────────────────────
    def _update_stats(self, result, latency_ms):
        with self._lock:
            s = self._stats
            s["total_analyzed"] += 1
            if result["threat"]:
                s["threats_detected"] += 1
            s["by_severity"][result["severity"]] += 1
            s["by_action"][result["action"]] += 1
            s["confidence_sum"] += result["confidence"]
            s["avg_confidence"] = s["confidence_sum"] / s["total_analyzed"]
            s["latency_sum"] += latency_ms
            s["avg_latency_ms"] = s["latency_sum"] / s["total_analyzed"]
            if result["threat"]:
                s["recent_threats"].append({
                    "ip":       result["ip"],
                    "action":   result["action"],
                    "severity": result["severity"],
                    "ts":       result["analyzed_at"],
                })

    def get_session_stats(self):
        with self._lock:
            s = self._stats
            uptime = time.time() - self._session_start
            return {
                "uptime_seconds":   round(uptime, 1),
                "total_analyzed":   s["total_analyzed"],
                "threats_detected": s["threats_detected"],
                "threat_rate":      round(s["threats_detected"] / max(s["total_analyzed"], 1), 4),
                "avg_confidence":   round(s["avg_confidence"], 4),
                "avg_latency_ms":   round(s["avg_latency_ms"], 3),
                "by_severity":      dict(s["by_severity"]),
                "by_action":        dict(s["by_action"]),
                "recent_threats":   list(s["recent_threats"])[-10:],
            }
