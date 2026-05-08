const express = require('express');
const router = express.Router();
const {
  ingestTelemetry,
  getThreats,
  getThreatById,
  acknowledgeThreat,
  deleteThreat,
  clearAllThreats,
} = require('../controllers/threatController');
const { protect, authorize } = require('../middleware/authMiddleware');

// Public telemetry ingestion (secured by rate limiter in server.js)
router.post('/', ingestTelemetry);

// Protected routes
router.get('/', protect, getThreats);
router.get('/:id', protect, getThreatById);
router.put('/:id/acknowledge', protect, authorize('admin', 'analyst'), acknowledgeThreat);
router.delete('/:id', protect, authorize('admin'), deleteThreat);
router.delete('/', protect, authorize('admin'), clearAllThreats);

module.exports = router;
