const crypto = require('crypto');
const Block = require('../models/Block');
const logger = require('./logger');

class Blockchain {
  constructor() {
    this.pendingQueue = [];
    this.isProcessing = false;
  }

  // ─── Hash Generation ───────────────────────────────────────────────────────
  calculateHash(index, timestamp, data, previousHash, nonce = 0) {
    const content = `${index}${timestamp}${JSON.stringify(data)}${previousHash}${nonce}`;
    return crypto.createHash('sha256').update(content).digest('hex');
  }

  // ─── Genesis Block ─────────────────────────────────────────────────────────
  async createGenesisBlock() {
    const existing = await Block.findOne({ index: 0 });
    if (existing) return existing;

    const genesis = new Block({
      index: 0,
      timestamp: new Date('2024-01-01T00:00:00Z'),
      data: {
        threatId: 'GENESIS',
        ip: '0.0.0.0',
        action: 'genesis',
        severity: 'LOW',
        threat: false,
        confidence: 1,
      },
      previousHash: '0000000000000000000000000000000000000000000000000000000000000000',
      hash: '',
      nonce: 0,
    });

    genesis.hash = this.calculateHash(
      genesis.index,
      genesis.timestamp,
      genesis.data,
      genesis.previousHash,
      genesis.nonce
    );

    await genesis.save();
    logger.info('Blockchain: Genesis block created');
    return genesis;
  }

  // ─── Get Latest Block ──────────────────────────────────────────────────────
  async getLatestBlock() {
    return Block.findOne().sort({ index: -1 });
  }

  // ─── Add Block ─────────────────────────────────────────────────────────────
  async addBlock(threatData) {
    try {
      // Ensure genesis exists
      await this.createGenesisBlock();

      const latestBlock = await this.getLatestBlock();
      const newIndex = latestBlock ? latestBlock.index + 1 : 1;
      const timestamp = new Date();

      const data = {
        threatId: threatData._id?.toString() || 'unknown',
        ip: threatData.ip,
        action: threatData.action,
        severity: threatData.severity,
        threat: threatData.threat,
        confidence: threatData.confidence || 0.5,
      };

      const previousHash = latestBlock?.hash || '0'.repeat(64);
      const hash = this.calculateHash(newIndex, timestamp, data, previousHash);

      const block = new Block({
        index: newIndex,
        timestamp,
        data,
        previousHash,
        hash,
        nonce: 0,
      });

      await block.save();
      logger.info(`Blockchain: Block #${newIndex} added | Hash: ${hash.substring(0, 16)}...`);
      return block;
    } catch (err) {
      logger.error(`Blockchain addBlock error: ${err.message}`);
      return null;
    }
  }

  // ─── Validate Chain Integrity ──────────────────────────────────────────────
  async validateChain() {
    const blocks = await Block.find().sort({ index: 1 });
    const results = { valid: true, totalBlocks: blocks.length, issues: [] };

    for (let i = 1; i < blocks.length; i++) {
      const current = blocks[i];
      const previous = blocks[i - 1];

      // Validate hash
      const recalculated = this.calculateHash(
        current.index,
        current.timestamp,
        current.data,
        current.previousHash,
        current.nonce
      );

      if (current.hash !== recalculated) {
        results.valid = false;
        results.issues.push({
          blockIndex: current.index,
          issue: 'Hash mismatch — block may have been tampered',
        });
      }

      // Validate chain link
      if (current.previousHash !== previous.hash) {
        results.valid = false;
        results.issues.push({
          blockIndex: current.index,
          issue: 'Chain link broken — previous hash does not match',
        });
      }
    }

    return results;
  }

  // ─── Get Recent Blocks ─────────────────────────────────────────────────────
  async getRecentBlocks(limit = 20) {
    return Block.find().sort({ index: -1 }).limit(limit);
  }

  // ─── Get Chain Stats ───────────────────────────────────────────────────────
  async getStats() {
    const [total, latest, oldest] = await Promise.all([
      Block.countDocuments(),
      Block.findOne().sort({ index: -1 }),
      Block.findOne({ index: 0 }),
    ]);
    return {
      totalBlocks: total,
      latestIndex: latest?.index || 0,
      latestHash: latest?.hash || '',
      genesisTimestamp: oldest?.timestamp || null,
      chainIntegrity: total > 0 ? 'verified' : 'empty',
    };
  }
}

module.exports = new Blockchain();
