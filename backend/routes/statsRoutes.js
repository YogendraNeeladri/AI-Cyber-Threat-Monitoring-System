const express = require('express');
const router = express.Router();
const {
  getOverview,
  getTimeline,
  getGeoDistribution,
  getSystemStatus,
  getBlockchainData,
} = require('../controllers/statsController');
const { protect } = require('../middleware/authMiddleware');

router.get('/overview', protect, getOverview);
router.get('/timeline', protect, getTimeline);
router.get('/geo', protect, getGeoDistribution);
router.get('/system', protect, getSystemStatus);
router.get('/blockchain', protect, getBlockchainData);

module.exports = router;
