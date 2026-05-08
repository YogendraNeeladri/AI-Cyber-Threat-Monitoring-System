"""
AI-Driven Cyber Threat Detection Engine
Flask REST API serving a trained ML pipeline
"""

import os
import sys
import time
import logging
import traceback
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from functools import wraps

from utils.logger import get_logger
from utils.model_manager import ModelManager
from utils.feature_engineer import FeatureEngineer
from utils.threat_analyzer import ThreatAnalyzer

# ─── App Setup ────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, origins=["http://localhost:3000", "http://localhost:5000"])

logger = get_logger("ai_server")

# ─── Global Components ────────────────────────────────────────────────────────
model_manager = ModelManager()
feature_engineer = FeatureEngineer()
threat_analyzer = ThreatAnalyzer(model_manager, feature_engineer)

# ─── Timing Decorator ─────────────────────────────────────────────────────────
def timed(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        start = time.perf_counter()
        result = f(*args, **kwargs)
        elapsed = (time.perf_counter() - start) * 1000
        logger.debug(f"{f.__name__} executed in {elapsed:.2f}ms")
        return result
    return wrapper

# ─── Request Validation ───────────────────────────────────────────────────────
def validate_telemetry(data):
    """Validate incoming telemetry payload."""
    if not data:
        return False, "Empty request body"
    if "ip" not in data:
        return False, "Missing required field: ip"
    if "action" not in data:
        return False, "Missing required field: action"

    valid_actions = [
        "login_attempt", "failed_login", "port_scan", "malware_activity",
        "file_access", "data_exfiltration", "brute_force", "sql_injection",
        "xss_attempt", "ddos", "ransomware", "privilege_escalation",
        "lateral_movement", "c2_communication", "dns_tunneling",
    ]
    if data["action"] not in valid_actions:
        return False, f"Invalid action: {data['action']}"

    return True, None

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    status = model_manager.get_status()
    return jsonify({
        "status": "online",
        "model": status["model_name"],
        "model_version": status["version"],
        "accuracy": status["accuracy"],
        "trained_on": status["trained_on"],
        "features": status["n_features"],
        "uptime_seconds": time.time() - app.start_time,
        "timestamp": datetime.utcnow().isoformat(),
    }), 200


@app.route("/analyze", methods=["POST"])
@timed
def analyze():
    """
    Main analysis endpoint.
    Accepts telemetry, returns threat classification.
    """
    try:
        data = request.get_json(force=True, silent=True)

        valid, err = validate_telemetry(data)
        if not valid:
            return jsonify({"error": err}), 400

        result = threat_analyzer.analyze(data)

        logger.info(
            f"ANALYZE | IP: {data.get('ip')} | Action: {data.get('action')} "
            f"| Severity: {result['severity']} | Confidence: {result['confidence']:.3f} "
            f"| Model: {result['model']}"
        )

        return jsonify(result), 200

    except Exception as e:
        logger.error(f"analyze error: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": "Analysis failed", "detail": str(e)}), 500


@app.route("/analyze/batch", methods=["POST"])
@timed
def analyze_batch():
    """
    Batch analysis endpoint — analyze up to 100 events at once.
    """
    try:
        data = request.get_json(force=True, silent=True)
        if not isinstance(data, list):
            return jsonify({"error": "Expected a JSON array of telemetry events"}), 400

        if len(data) > 100:
            return jsonify({"error": "Batch limit is 100 events per request"}), 400

        results = []
        for item in data:
            valid, err = validate_telemetry(item)
            if not valid:
                results.append({"error": err, "input": item})
                continue
            result = threat_analyzer.analyze(item)
            results.append(result)

        high_count = sum(1 for r in results if r.get("severity") in ["HIGH", "CRITICAL"])
        logger.info(f"BATCH | {len(data)} events | {high_count} high/critical threats")

        return jsonify({
            "results": results,
            "summary": {
                "total": len(results),
                "threats_detected": sum(1 for r in results if r.get("threat")),
                "high_critical": high_count,
            }
        }), 200

    except Exception as e:
        logger.error(f"analyze_batch error: {str(e)}")
        return jsonify({"error": "Batch analysis failed"}), 500


@app.route("/model/info", methods=["GET"])
def model_info():
    """Detailed model information and feature importances."""
    try:
        info = model_manager.get_detailed_info()
        return jsonify(info), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/model/retrain", methods=["POST"])
def retrain():
    """
    Trigger model retraining with fresh synthetic data.
    POST with optional body: { "samples": 5000 }
    """
    try:
        body = request.get_json(silent=True) or {}
        samples = min(50000, max(1000, int(body.get("samples", 10000))))

        logger.info(f"Retraining triggered with {samples} samples...")
        metrics = model_manager.train(n_samples=samples, force=True)

        return jsonify({
            "success": True,
            "message": f"Model retrained on {samples} samples",
            "metrics": metrics,
        }), 200

    except Exception as e:
        logger.error(f"retrain error: {str(e)}")
        return jsonify({"error": "Retraining failed", "detail": str(e)}), 500


@app.route("/features/explain", methods=["POST"])
@timed
def explain():
    """
    Return feature importance breakdown for a specific telemetry event.
    """
    try:
        data = request.get_json(force=True, silent=True)
        valid, err = validate_telemetry(data)
        if not valid:
            return jsonify({"error": err}), 400

        explanation = threat_analyzer.explain(data)
        return jsonify(explanation), 200

    except Exception as e:
        logger.error(f"explain error: {str(e)}")
        return jsonify({"error": "Explanation failed"}), 500


@app.route("/stats", methods=["GET"])
def stats():
    """Runtime statistics for this analysis session."""
    return jsonify(threat_analyzer.get_session_stats()), 200


# ─── Error Handlers ───────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405

@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error"}), 500


# ─── Startup ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.start_time = time.time()

    PORT = int(os.environ.get("AI_PORT", 7000))
    DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

    logger.info("=" * 55)
    logger.info("  AI Cyber Threat Detection Engine v1.0")
    logger.info(f"  Starting on port {PORT}")
    logger.info("=" * 55)

    # Train model on startup if not already trained
    if not model_manager.is_trained():
        logger.info("No saved model found. Training on startup...")
        model_manager.train(n_samples=15000)
    else:
        logger.info("Loaded pre-trained model from disk.")

    logger.info(f"Model ready: {model_manager.get_status()['model_name']}")
    logger.info(f"Accuracy:    {model_manager.get_status()['accuracy']:.4f}")
    logger.info("=" * 55)

    app.run(
        host="0.0.0.0",
        port=PORT,
        debug=DEBUG,
        threaded=True,
        use_reloader=False,
    )
