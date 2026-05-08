const mongoose = require('mongoose');

const blockSchema = new mongoose.Schema(
  {
    index: {
      type: Number,
      required: true,
      unique: true,
    },
    timestamp: {
      type: Date,
      required: true,
      default: Date.now,
    },
    data: {
      threatId: String,
      ip: String,
      action: String,
      severity: String,
      threat: Boolean,
      confidence: Number,
    },
    previousHash: {
      type: String,
      required: true,
    },
    hash: {
      type: String,
      required: true,
      unique: true,
    },
    nonce: {
      type: Number,
      default: 0,
    },
  },
  { timestamps: true }
);

blockSchema.index({ hash: 1 });
blockSchema.index({ index: 1 });
blockSchema.index({ 'data.threatId': 1 });

module.exports = mongoose.model('Block', blockSchema);
