const mongoose = require('mongoose');

const threatSchema = new mongoose.Schema(
  {
    ip: {
      type: String,
      required: [true, 'IP address is required'],
      trim: true,
      match: [
        /^(\d{1,3}\.){3}\d{1,3}$|^([a-fA-F0-9:]+)$/,
        'Invalid IP address format',
      ],
    },
    action: {
      type: String,
      required: [true, 'Action type is required'],
      enum: {
        values: [
          'login_attempt',
          'failed_login',
          'port_scan',
          'malware_activity',
          'file_access',
          'data_exfiltration',
          'brute_force',
          'sql_injection',
          'xss_attempt',
          'ddos',
          'ransomware',
          'privilege_escalation',
          'lateral_movement',
          'c2_communication',
          'dns_tunneling',
        ],
        message: '{VALUE} is not a valid action type',
      },
    },
    severity: {
      type: String,
      enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
      required: true,
      default: 'LOW',
    },
    threat: {
      type: Boolean,
      required: true,
      default: false,
    },
    confidence: {
      type: Number,
      min: 0,
      max: 1,
      default: 0.5,
    },
    // AI engine metadata
    aiModel: {
      type: String,
      default: 'RandomForestClassifier',
    },
    aiVersion: {
      type: String,
      default: '1.0.0',
    },
    // Geo data
    geo: {
      country: { type: String, default: 'Unknown' },
      countryCode: { type: String, default: 'XX' },
      region: { type: String, default: 'Unknown' },
      city: { type: String, default: 'Unknown' },
      lat: { type: Number, default: 0 },
      lon: { type: Number, default: 0 },
      isp: { type: String, default: 'Unknown' },
      org: { type: String, default: 'Unknown' },
      timezone: { type: String, default: 'UTC' },
    },
    // Extra telemetry fields
    telemetry: {
      loginAttempts: { type: Number, default: 0 },
      portScans: { type: Number, default: 0 },
      malwareDetected: { type: Number, default: 0 },
      dataTransferred: { type: Number, default: 0 }, // bytes
      requestCount: { type: Number, default: 1 },
      userAgent: { type: String, default: '' },
      protocol: { type: String, default: 'TCP' },
      port: { type: Number, default: 0 },
      duration: { type: Number, default: 0 }, // ms
    },
    // Blockchain integrity
    /*blockHash: {
      type: String,
      default: '',
    },*/
    blockHash: {
    type: String,
    default: null,
    },
    blockIndex: {
      type: Number,
      default: 0,
    },
    // Alert status
    acknowledged: {
      type: Boolean,
      default: false,
    },
    acknowledgedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: null,
    },
    acknowledgedAt: {
      type: Date,
      default: null,
    },
    notes: {
      type: String,
      default: '',
      maxlength: 1000,
    },
    // Source system
    source: {
      type: String,
      default: 'telemetry_api',
    },
    rawPayload: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
  },
  {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true },
  }
);

// ─── Indexes ──────────────────────────────────────────────────────────────────
threatSchema.index({ severity: 1, createdAt: -1 });
threatSchema.index({ ip: 1, createdAt: -1 });
threatSchema.index({ action: 1, createdAt: -1 });
threatSchema.index({ threat: 1, createdAt: -1 });
threatSchema.index({ acknowledged: 1 });
threatSchema.index({ createdAt: -1 });
threatSchema.index({ 'geo.countryCode': 1 });
threatSchema.index({ blockHash: 1 }, { sparse: true });
/*threatSchema.index({ blockHash: 1 }, { unique: true, sparse: true });*/

// ─── Virtuals ─────────────────────────────────────────────────────────────────
threatSchema.virtual('age').get(function () {
  return Date.now() - this.createdAt.getTime();
});

threatSchema.virtual('severityScore').get(function () {
  const scores = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
  return scores[this.severity] || 0;
});

// ─── Static Methods ───────────────────────────────────────────────────────────
threatSchema.statics.getStats = async function () {
  const [counts, severityCounts, topIPs, topActions, recent] = await Promise.all([
    this.countDocuments(),
    this.aggregate([
      { $group: { _id: '$severity', count: { $sum: 1 } } },
    ]),
    this.aggregate([
      { $group: { _id: '$ip', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 },
    ]),
    this.aggregate([
      { $group: { _id: '$action', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 },
    ]),
    this.find({ threat: true })
      .sort({ createdAt: -1 })
      .limit(10)
      .select('ip action severity createdAt geo'),
  ]);

  const severityMap = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
  severityCounts.forEach((s) => (severityMap[s._id] = s.count));

  return {
    total: counts,
    severity: severityMap,
    topIPs,
    topActions,
    recentThreats: recent,
  };
};

threatSchema.statics.getTimelineSeries = async function (hours = 24) {
  const since = new Date(Date.now() - hours * 60 * 60 * 1000);
  return this.aggregate([
    { $match: { createdAt: { $gte: since } } },
    {
      $group: {
        _id: {
          hour: { $hour: '$createdAt' },
          severity: '$severity',
        },
        count: { $sum: 1 },
      },
    },
    { $sort: { '_id.hour': 1 } },
  ]);
};

threatSchema.statics.getGeoDistribution = async function () {
  return this.aggregate([
    { $match: { threat: true } },
    {
      $group: {
        _id: '$geo.countryCode',
        country: { $first: '$geo.country' },
        count: { $sum: 1 },
        lat: { $first: '$geo.lat' },
        lon: { $first: '$geo.lon' },
      },
    },
    { $sort: { count: -1 } },
    { $limit: 50 },
  ]);
};

// ─── Pre-save Hook ────────────────────────────────────────────────────────────
threatSchema.pre('save', function (next) {
  if (this.severity === 'CRITICAL' || this.severity === 'HIGH') {
    this.threat = true;
  }
  next();
});

module.exports = mongoose.model('Threat', threatSchema);
