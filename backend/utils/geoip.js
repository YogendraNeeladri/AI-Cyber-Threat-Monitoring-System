const axios = require('axios');
const logger = require('./logger');

// In-memory cache to avoid repeated lookups
const geoCache = new Map();
const CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

// Known private/reserved IP ranges
const isPrivateIP = (ip) => {
  const privateRanges = [
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[01])\./,
    /^192\.168\./,
    /^127\./,
    /^::1$/,
    /^localhost$/,
    /^0\.0\.0\.0$/,
  ];
  return privateRanges.some((r) => r.test(ip));
};

const lookupGeo = async (ip) => {
  if (isPrivateIP(ip)) {
    return {
      country: 'Local Network',
      countryCode: 'LN',
      region: 'Internal',
      city: 'localhost',
      lat: 0,
      lon: 0,
      isp: 'Private',
      org: 'Internal Network',
      timezone: 'UTC',
    };
  }

  // Check cache
  const cached = geoCache.get(ip);
  if (cached && Date.now() - cached.ts < CACHE_TTL) {
    return cached.data;
  }

  try {
    // Using ip-api.com (free tier, no key needed for dev)
    const response = await axios.get(`http://ip-api.com/json/${ip}?fields=66846719`, {
      timeout: 3000,
    });

    const d = response.data;

    if (d.status === 'success') {
      const geoData = {
        country: d.country || 'Unknown',
        countryCode: d.countryCode || 'XX',
        region: d.regionName || 'Unknown',
        city: d.city || 'Unknown',
        lat: d.lat || 0,
        lon: d.lon || 0,
        isp: d.isp || 'Unknown',
        org: d.org || 'Unknown',
        timezone: d.timezone || 'UTC',
      };

      // Cache the result
      geoCache.set(ip, { data: geoData, ts: Date.now() });
      return geoData;
    }

    return getDefaultGeo();
  } catch (err) {
    logger.warn(`GeoIP lookup failed for ${ip}: ${err.message}`);
    return getDefaultGeo();
  }
};

const getDefaultGeo = () => ({
  country: 'Unknown',
  countryCode: 'XX',
  region: 'Unknown',
  city: 'Unknown',
  lat: 0,
  lon: 0,
  isp: 'Unknown',
  org: 'Unknown',
  timezone: 'UTC',
});

const getCacheSize = () => geoCache.size;

const clearCache = () => {
  geoCache.clear();
  logger.info('GeoIP cache cleared');
};

module.exports = { lookupGeo, getCacheSize, clearCache };
