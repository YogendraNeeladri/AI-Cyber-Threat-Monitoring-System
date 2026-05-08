const express = require('express');
const router = express.Router();
const { lookupGeo, clearCache } = require('../utils/geoip');
const { protect, authorize } = require('../middleware/authMiddleware');

router.get('/lookup/:ip', protect, async (req, res) => {
  try {
    const data = await lookupGeo(req.params.ip);
    res.json({ success: true, data });
  } catch (err) {
    res.status(500).json({ error: 'GeoIP lookup failed' });
  }
});

router.delete('/cache', protect, authorize('admin'), (req, res) => {
  clearCache();
  res.json({ success: true, message: 'GeoIP cache cleared' });
});

module.exports = router;
