const axios = require('axios');
const logger = require('./logger');

const AI_ENGINE_URL = process.env.AI_ENGINE_URL || 'http://127.0.0.1:7000';
const AI_TIMEOUT = parseInt(process.env.AI_TIMEOUT_MS) || 5000;

// Fallback rule-based classifier when AI engine is unavailable
const ruleBased = (telemetry) => {
  const { action, telemetry: t } = telemetry;

  const HIGH_ACTIONS = [
    'malware_activity',
    'ransomware',
    'data_exfiltration',
    'c2_communication',
    'ddos',
    'privilege_escalation',
    'lateral_movement',
    'dns_tunneling',
  ];
  const MEDIUM_ACTIONS = [
    'port_scan',
    'brute_force',
    'sql_injection',
    'xss_attempt',
    'failed_login',
  ];

  if (HIGH_ACTIONS.includes(action)) {
    return { severity: 'HIGH', threat: true, confidence: 0.85, model: 'rule-based-fallback' };
  }
  if (MEDIUM_ACTIONS.includes(action)) {
    const loginBurst = (t?.loginAttempts || 0) > 10;
    return {
      severity: loginBurst ? 'HIGH' : 'MEDIUM',
      threat: true,
      confidence: 0.7,
      model: 'rule-based-fallback',
    };
  }

  // Check telemetry thresholds
  if ((t?.portScans || 0) > 50) {
    return { severity: 'HIGH', threat: true, confidence: 0.9, model: 'rule-based-fallback' };
  }
  if ((t?.malwareDetected || 0) > 0) {
    return { severity: 'CRITICAL', threat: true, confidence: 0.95, model: 'rule-based-fallback' };
  }

  return { severity: 'LOW', threat: false, confidence: 0.6, model: 'rule-based-fallback' };
};

const analyzeWithAI = async (telemetryData) => {
  try {
    const response = await axios.post(`${AI_ENGINE_URL}/analyze`, telemetryData, {
      timeout: AI_TIMEOUT,
      headers: { 'Content-Type': 'application/json' },
    });

    const result = response.data;
    return {
      severity: result.severity || 'LOW',
      threat: result.threat ?? false,
      confidence: result.confidence || 0.5,
      model: result.model || 'ai-engine',
      features: result.features || {},
    };
  } catch (err) {
    if (err.code === 'ECONNREFUSED' || err.code === 'ETIMEDOUT') {
      logger.warn('AI Engine unavailable — using rule-based fallback classifier');
    } else {
      logger.error(`AI Engine error: ${err.message}`);
    }
    return ruleBased(telemetryData);
  }
};

const checkHealth = async () => {
  try {
    const response = await axios.get(`${AI_ENGINE_URL}/health`, { timeout: 2000 });
    return { online: true, ...response.data };
  } catch {
    return { online: false, model: 'offline' };
  }
};

module.exports = { analyzeWithAI, checkHealth, ruleBased };
