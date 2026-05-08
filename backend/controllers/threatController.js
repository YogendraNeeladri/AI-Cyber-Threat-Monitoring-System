const Threat = require('../models/Threat');
const { analyzeWithAI } = require('../utils/aiClient');
const { lookupGeo } = require('../utils/geoip');
const blockchain = require('../utils/blockchain');
const logger = require('../utils/logger');

// ─── POST /api/telemetry ───────────────────────────────────────────────────
// Ingest raw telemetry, run AI, store + broadcast

const ingestTelemetry = async (req, res) => {
  try {
    const body = req.body;
    const ip     = body.ip;
    const action = body.action;

    if (!ip || !action) {
      return res.status(400).json({ error: 'ip and action are required fields' });
    }

    // Support BOTH flat payload (simulator) and nested telemetry object
    const tel = body.telemetry || {};
    const loginAttempts   = body.loginAttempts   ?? tel.loginAttempts   ?? 0;
    const portScans       = body.portScans       ?? tel.portScans       ?? 0;
    const malwareDetected = body.malwareDetected ?? tel.malwareDetected ?? 0;
    const dataTransferred = body.dataTransferred ?? tel.dataTransferred ?? 0;
    const requestCount    = body.requestCount    ?? tel.requestCount    ?? 1;
    const userAgent       = body.userAgent       ?? tel.userAgent       ?? '';
    const protocol        = body.protocol        ?? tel.protocol        ?? 'TCP';
    const port            = body.port            ?? tel.port            ?? 0;
    const source          = body.source          ?? 'api';

    const telemetryPayload = {
      ip,
      action,
      telemetry: {
        loginAttempts,
        portScans,
        malwareDetected,
        dataTransferred,
        requestCount,
        userAgent,
        protocol,
        port,
      },
    };

    const [aiResult, geoData] = await Promise.all([
      analyzeWithAI(telemetryPayload),
      lookupGeo(ip),
    ]);

    const threat = new Threat({
      ip,
      action,
      severity:  aiResult.severity,
      threat:    aiResult.threat,
      confidence:aiResult.confidence,
      aiModel:   aiResult.model || 'EnsembleVotingClassifier',
      geo:       geoData,
      telemetry: {
        loginAttempts,
        portScans,
        malwareDetected,
        dataTransferred,
        requestCount,
        userAgent,
        protocol,
        port,
      },
      source,
      rawPayload: body,
    });

    await threat.save();

    // Blockchain async — non blocking
    blockchain.addBlock(threat).then((block) => {
      if (block) {
        Threat.findByIdAndUpdate(threat._id, {
          blockHash:  block.hash,
          blockIndex: block.index,
        }).exec();
      }
    });

    const io = req.app.get('io');
    if (io) {
      const eventPayload = {
        _id:        threat._id,
        ip,
        action,
        severity:   aiResult.severity,
        threat:     aiResult.threat,
        confidence: aiResult.confidence,
        geo:        geoData,
        timestamp:  threat.createdAt,
        model:      aiResult.model,
      };
      io.to('threats').emit('new_threat', eventPayload);
      io.to(`severity_${aiResult.severity}`).emit('severity_alert', eventPayload);
      if (['HIGH','CRITICAL'].includes(aiResult.severity)) {
        io.to('threats').emit('high_alert', eventPayload);
      }
    }

    logger.info(`Threat ingested: ${ip} | ${action} | ${aiResult.severity} | ${(aiResult.confidence*100).toFixed(1)}%`);

    return res.status(201).json({
      success: true,
      threat: {
        _id:        threat._id,
        ip,
        action,
        severity:   aiResult.severity,
        threat:     aiResult.threat,
        confidence: aiResult.confidence,
        geo:        geoData,
        timestamp:  threat.createdAt,
      },
    });
  } catch (err) {
    logger.error(`ingestTelemetry error: ${err.message}\n${err.stack}`);
    return res.status(500).json({ error: 'Internal server error', detail: err.message });
  }
};

/*
const ingestTelemetry = async (req, res) => {
  try {
    const {
      ip,
      action,
      loginAttempts = 0,
      portScans = 0,
      malwareDetected = 0,
      dataTransferred = 0,
      requestCount = 1,
      userAgent = '',
      protocol = 'TCP',
      port = 0,
      source = 'api',
    } = req.body;

    // Input validation
    if (!ip || !action) {
      return res.status(400).json({ error: 'ip and action are required fields' });
    }

    // Build telemetry payload for AI
    const telemetryPayload = {
      ip,
      action,
      telemetry: {
        loginAttempts,
        portScans,
        malwareDetected,
        dataTransferred,
        requestCount,
        userAgent,
        protocol,
        port,
      },
    };

    // Run AI analysis + GeoIP in parallel
    const [aiResult, geoData] = await Promise.all([
      analyzeWithAI(telemetryPayload),
      lookupGeo(ip),
    ]);

    // Create threat record
    const threat = new Threat({
      ip,
      action,
      severity: aiResult.severity,
      threat: aiResult.threat,
      confidence: aiResult.confidence,
      aiModel: aiResult.model || 'RandomForestClassifier',
      geo: geoData,
      telemetry: {
        loginAttempts,
        portScans,
        malwareDetected,
        dataTransferred,
        requestCount,
        userAgent,
        protocol,
        port,
      },
      source,
      rawPayload: req.body,
    });

    await threat.save();

    // Add to blockchain asynchronously (non-blocking)
    blockchain.addBlock(threat).then((block) => {
      if (block) {
        Threat.findByIdAndUpdate(threat._id, {
          blockHash: block.hash,
          blockIndex: block.index,
        }).exec();
      }
    });

    // Emit real-time events via Socket.IO
    const io = req.app.get('io');
    if (io) {
      const eventPayload = {
        _id: threat._id,
        ip,
        action,
        severity: aiResult.severity,
        threat: aiResult.threat,
        confidence: aiResult.confidence,
        geo: geoData,
        timestamp: threat.createdAt,
        model: aiResult.model,
      };

      // Broadcast to all connected clients
      io.to('threats').emit('new_threat', eventPayload);

      // Broadcast to severity-specific rooms
      io.to(`severity_${aiResult.severity}`).emit('severity_alert', eventPayload);

      // High-priority broadcast
      if (aiResult.severity === 'HIGH' || aiResult.severity === 'CRITICAL') {
        io.to('threats').emit('high_alert', eventPayload);
      }
    }

    logger.info(
      `Threat ingested: ${ip} | ${action} | ${aiResult.severity} | confidence: ${(aiResult.confidence * 100).toFixed(1)}%`
    );

    return res.status(201).json({
      success: true,
      threat: {
        _id: threat._id,
        ip,
        action,
        severity: aiResult.severity,
        threat: aiResult.threat,
        confidence: aiResult.confidence,
        geo: geoData,
        timestamp: threat.createdAt,
      },
    });
  } catch (err) {
    logger.error(`ingestTelemetry error: ${err.message}`);
    return res.status(500).json({ error: 'Internal server error during telemetry ingestion' });
  }
};
*/
// ─── GET /api/threats ──────────────────────────────────────────────────────
const getThreats = async (req, res) => {
  try {
    const {
      page = 1,
      limit = 50,
      severity,
      action,
      ip,
      threat,
      acknowledged,
      from,
      to,
      sort = '-createdAt',
    } = req.query;

    const filter = {};
    if (severity) filter.severity = { $in: severity.split(',') };
    if (action) filter.action = { $in: action.split(',') };
    if (ip) filter.ip = { $regex: ip, $options: 'i' };
    if (threat !== undefined) filter.threat = threat === 'true';
    if (acknowledged !== undefined) filter.acknowledged = acknowledged === 'true';
    if (from || to) {
      filter.createdAt = {};
      if (from) filter.createdAt.$gte = new Date(from);
      if (to) filter.createdAt.$lte = new Date(to);
    }

    const pageNum = Math.max(1, parseInt(page));
    const limitNum = Math.min(200, Math.max(1, parseInt(limit)));
    const skip = (pageNum - 1) * limitNum;

    const [threats, total] = await Promise.all([
      Threat.find(filter)
        .sort(sort)
        .skip(skip)
        .limit(limitNum)
        .select('-rawPayload')
        .lean(),
      Threat.countDocuments(filter),
    ]);

    return res.json({
      success: true,
      data: threats,
      pagination: {
        total,
        page: pageNum,
        limit: limitNum,
        pages: Math.ceil(total / limitNum),
        hasNext: pageNum * limitNum < total,
        hasPrev: pageNum > 1,
      },
    });
  } catch (err) {
    logger.error(`getThreats error: ${err.message}`);
    return res.status(500).json({ error: 'Failed to retrieve threats' });
  }
};

// ─── GET /api/threats/:id ──────────────────────────────────────────────────
const getThreatById = async (req, res) => {
  try {
    const threat = await Threat.findById(req.params.id);
    if (!threat) return res.status(404).json({ error: 'Threat not found' });
    return res.json({ success: true, data: threat });
  } catch (err) {
    logger.error(`getThreatById error: ${err.message}`);
    return res.status(500).json({ error: 'Failed to retrieve threat' });
  }
};

// ─── PUT /api/threats/:id/acknowledge ─────────────────────────────────────
const acknowledgeThreat = async (req, res) => {
  try {
    const { notes } = req.body;
    const threat = await Threat.findByIdAndUpdate(
      req.params.id,
      {
        acknowledged: true,
        acknowledgedBy: req.user?._id || null,
        acknowledgedAt: new Date(),
        notes: notes || '',
      },
      { new: true }
    );

    if (!threat) return res.status(404).json({ error: 'Threat not found' });

    // Notify dashboard
    const io = req.app.get('io');
    if (io) {
      io.to('threats').emit('threat_acknowledged', {
        _id: threat._id,
        acknowledgedAt: threat.acknowledgedAt,
        acknowledgedBy: req.user?.name || 'System',
      });
    }

    return res.json({ success: true, data: threat });
  } catch (err) {
    logger.error(`acknowledgeThreat error: ${err.message}`);
    return res.status(500).json({ error: 'Failed to acknowledge threat' });
  }
};

// ─── DELETE /api/threats/:id ───────────────────────────────────────────────
const deleteThreat = async (req, res) => {
  try {
    const threat = await Threat.findByIdAndDelete(req.params.id);
    if (!threat) return res.status(404).json({ error: 'Threat not found' });
    return res.json({ success: true, message: 'Threat record deleted' });
  } catch (err) {
    logger.error(`deleteThreat error: ${err.message}`);
    return res.status(500).json({ error: 'Failed to delete threat' });
  }
};

// ─── DELETE /api/threats ───────────────────────────────────────────────────
const clearAllThreats = async (req, res) => {
  try {
    const result = await Threat.deleteMany({});
    logger.warn(`All threats cleared: ${result.deletedCount} records deleted`);

    const io = req.app.get('io');
    if (io) io.to('threats').emit('threats_cleared', { count: result.deletedCount });

    return res.json({ success: true, deleted: result.deletedCount });
  } catch (err) {
    logger.error(`clearAllThreats error: ${err.message}`);
    return res.status(500).json({ error: 'Failed to clear threats' });
  }
};

module.exports = {
  ingestTelemetry,
  getThreats,
  getThreatById,
  acknowledgeThreat,
  deleteThreat,
  clearAllThreats,
};
