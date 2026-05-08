const Threat = require('../models/Threat');
const blockchain = require('../utils/blockchain');
const { checkHealth } = require('../utils/aiClient');
const { getCacheSize } = require('../utils/geoip');
const logger = require('../utils/logger');
const mongoose = require('mongoose');

// ─── GET /api/stats/overview ───────────────────────────────────────────────
const getOverview = async (req, res) => {
  try {
    const now = new Date();
    const last24h = new Date(now - 24 * 60 * 60 * 1000);
    const last1h = new Date(now - 60 * 60 * 1000);

    const [
      totalThreats,
      last24hThreats,
      last1hThreats,
      severityBreakdown,
      actionBreakdown,
      acknowledgedCount,
      topIPs,
      unacknowledgedHigh,
    ] = await Promise.all([
      Threat.countDocuments(),
      Threat.countDocuments({ createdAt: { $gte: last24h } }),
      Threat.countDocuments({ createdAt: { $gte: last1h } }),
      Threat.aggregate([
        { $group: { _id: '$severity', count: { $sum: 1 } } },
      ]),
      Threat.aggregate([
        { $group: { _id: '$action', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 8 },
      ]),
      Threat.countDocuments({ acknowledged: true }),
      Threat.aggregate([
        { $group: { _id: '$ip', count: { $sum: 1 }, lastSeen: { $max: '$createdAt' } } },
        { $sort: { count: -1 } },
        { $limit: 10 },
      ]),
      Threat.countDocuments({
        threat: true,
        acknowledged: false,
        severity: { $in: ['HIGH', 'CRITICAL'] },
      }),
    ]);

    const severityMap = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
    severityBreakdown.forEach((s) => (severityMap[s._id] = s.count));

    return res.json({
      success: true,
      data: {
        totals: {
          all: totalThreats,
          last24h: last24hThreats,
          last1h: last1hThreats,
          acknowledged: acknowledgedCount,
          unacknowledgedHigh,
        },
        severity: severityMap,
        actions: actionBreakdown,
        topIPs,
        threatRate: {
          perHour: last1hThreats,
          per24h: last24hThreats,
        },
      },
    });
  } catch (err) {
    logger.error(`getOverview error: ${err.message}`);
    return res.status(500).json({ error: 'Failed to get overview stats' });
  }
};

// ─── GET /api/stats/timeline ───────────────────────────────────────────────
const getTimeline = async (req, res) => {
  try {
    const hours = Math.min(168, Math.max(1, parseInt(req.query.hours) || 24));
    const since = new Date(Date.now() - hours * 60 * 60 * 1000);

    const bucketMinutes = hours <= 6 ? 10 : hours <= 24 ? 60 : 360;

    const timeline = await Threat.aggregate([
      { $match: { createdAt: { $gte: since } } },
      {
        $group: {
          _id: {
            bucket: {
              $subtract: [
                { $toLong: '$createdAt' },
                {
                  $mod: [
                    { $toLong: '$createdAt' },
                    bucketMinutes * 60 * 1000,
                  ],
                },
              ],
            },
            severity: '$severity',
          },
          count: { $sum: 1 },
        },
      },
      {
        $group: {
          _id: '$_id.bucket',
          severities: {
            $push: { severity: '$_id.severity', count: '$count' },
          },
          total: { $sum: '$count' },
        },
      },
      { $sort: { _id: 1 } },
    ]);

    // Normalize
    const formatted = timeline.map((bucket) => {
      const s = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
      bucket.severities.forEach((sv) => (s[sv.severity] = sv.count));
      return {
        timestamp: new Date(bucket._id).toISOString(),
        total: bucket.total,
        ...s,
      };
    });

    return res.json({ success: true, data: formatted, bucketMinutes });
  } catch (err) {
    logger.error(`getTimeline error: ${err.message}`);
    return res.status(500).json({ error: 'Failed to get timeline data' });
  }
};

// ─── GET /api/stats/geo ────────────────────────────────────────────────────
const getGeoDistribution = async (req, res) => {
  try {
    const geoData = await Threat.aggregate([
      { $match: { threat: true } },
      {
        $group: {
          _id: '$geo.countryCode',
          country: { $first: '$geo.country' },
          count: { $sum: 1 },
          lat: { $first: '$geo.lat' },
          lon: { $first: '$geo.lon' },
          severities: { $push: '$severity' },
          actions: { $push: '$action' },
        },
      },
      { $sort: { count: -1 } },
      { $limit: 100 },
    ]);

    return res.json({ success: true, data: geoData });
  } catch (err) {
    logger.error(`getGeoDistribution error: ${err.message}`);
    return res.status(500).json({ error: 'Failed to get geo data' });
  }
};

// ─── GET /api/stats/system ─────────────────────────────────────────────────
const getSystemStatus = async (req, res) => {
  try {
    const [aiHealth, blockchainStats] = await Promise.all([
      checkHealth(),
      blockchain.getStats(),
    ]);

    return res.json({
      success: true,
      data: {
        server: {
          status: 'online',
          uptime: process.uptime(),
          memory: process.memoryUsage(),
          nodeVersion: process.version,
          env: process.env.NODE_ENV || 'development',
        },
        mongodb: {
          status: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
          host: mongoose.connection.host,
          dbName: mongoose.connection.name,
        },
        aiEngine: aiHealth,
        blockchain: blockchainStats,
        geoipCache: { entries: getCacheSize() },
        timestamp: new Date().toISOString(),
      },
    });
  } catch (err) {
    logger.error(`getSystemStatus error: ${err.message}`);
    return res.status(500).json({ error: 'Failed to get system status' });
  }
};

// ─── GET /api/stats/blockchain ─────────────────────────────────────────────
const getBlockchainData = async (req, res) => {
  try {
    const { limit = 20 } = req.query;
    const [blocks, validation] = await Promise.all([
      blockchain.getRecentBlocks(parseInt(limit)),
      blockchain.validateChain(),
    ]);
    return res.json({ success: true, blocks, validation });
  } catch (err) {
    logger.error(`getBlockchainData error: ${err.message}`);
    return res.status(500).json({ error: 'Failed to get blockchain data' });
  }
};

module.exports = {
  getOverview,
  getTimeline,
  getGeoDistribution,
  getSystemStatus,
  getBlockchainData,
};
