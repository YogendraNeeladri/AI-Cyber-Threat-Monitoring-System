const mongoose = require('mongoose');
const dotenv = require('dotenv');
dotenv.config();

const User = require('../models/User');
const Threat = require('../models/Threat');
const blockchain = require('../utils/blockchain');

const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/cyberthreat';

const sampleThreats = [
  { ip: '185.220.101.45', action: 'port_scan', severity: 'HIGH', threat: true, confidence: 0.92,
    geo: { country: 'Russia', countryCode: 'RU', city: 'Moscow', lat: 55.75, lon: 37.61 } },
  { ip: '45.141.84.120', action: 'brute_force', severity: 'HIGH', threat: true, confidence: 0.88,
    geo: { country: 'China', countryCode: 'CN', city: 'Beijing', lat: 39.90, lon: 116.40 } },
  { ip: '104.21.45.67', action: 'malware_activity', severity: 'CRITICAL', threat: true, confidence: 0.97,
    geo: { country: 'United States', countryCode: 'US', city: 'Chicago', lat: 41.85, lon: -87.65 } },
  { ip: '192.168.1.105', action: 'failed_login', severity: 'MEDIUM', threat: true, confidence: 0.65,
    geo: { country: 'Local Network', countryCode: 'LN', city: 'localhost', lat: 0, lon: 0 } },
  { ip: '77.88.55.88', action: 'sql_injection', severity: 'HIGH', threat: true, confidence: 0.91,
    geo: { country: 'Germany', countryCode: 'DE', city: 'Berlin', lat: 52.52, lon: 13.40 } },
  { ip: '198.51.100.23', action: 'data_exfiltration', severity: 'CRITICAL', threat: true, confidence: 0.96,
    geo: { country: 'Brazil', countryCode: 'BR', city: 'São Paulo', lat: -23.54, lon: -46.63 } },
  { ip: '10.0.0.55', action: 'login_attempt', severity: 'LOW', threat: false, confidence: 0.3,
    geo: { country: 'Local Network', countryCode: 'LN', city: 'localhost', lat: 0, lon: 0 } },
  { ip: '91.108.4.100', action: 'ddos', severity: 'CRITICAL', threat: true, confidence: 0.99,
    geo: { country: 'Ukraine', countryCode: 'UA', city: 'Kyiv', lat: 50.45, lon: 30.52 } },
  { ip: '203.0.113.50', action: 'dns_tunneling', severity: 'HIGH', threat: true, confidence: 0.87,
    geo: { country: 'India', countryCode: 'IN', city: 'Mumbai', lat: 19.07, lon: 72.87 } },
  { ip: '192.0.2.78', action: 'xss_attempt', severity: 'MEDIUM', threat: true, confidence: 0.72,
    geo: { country: 'United Kingdom', countryCode: 'GB', city: 'London', lat: 51.50, lon: -0.12 } },
];

const seed = async () => {
  try {
    await mongoose.connect(MONGO_URI);
    console.log('Connected to MongoDB');

    // Clear existing data
    await Promise.all([User.deleteMany(), Threat.deleteMany()]);
    console.log('Cleared existing data');

    // Create users
    const admin = await User.create({
      name: 'Admin User',
      email: 'admin@cyberthreat.local',
      password: 'Admin@123456',
      role: 'admin',
    });
    await User.create({
      name: 'SOC Analyst',
      email: 'analyst@cyberthreat.local',
      password: 'Analyst@123456',
      role: 'analyst',
    });
    await User.create({
      name: 'Dashboard Viewer',
      email: 'viewer@cyberthreat.local',
      password: 'Viewer@123456',
      role: 'viewer',
    });
    console.log('Users created');

    // Create sample threats with timestamps spread over last 24h
    for (let i = 0; i < sampleThreats.length; i++) {
      const hoursAgo = Math.floor(Math.random() * 24);
      const threat = await Threat.create({
        ...sampleThreats[i],
        createdAt: new Date(Date.now() - hoursAgo * 60 * 60 * 1000),
      });
      await blockchain.addBlock(threat);
    }
    console.log(`${sampleThreats.length} sample threats created`);

    console.log('\n─────────────────────────────────────────');
    console.log('Seed complete! Login credentials:');
    console.log('  Admin:   admin@cyberthreat.local / Admin@123456');
    console.log('  Analyst: analyst@cyberthreat.local / Analyst@123456');
    console.log('  Viewer:  viewer@cyberthreat.local / Viewer@123456');
    console.log('─────────────────────────────────────────\n');

    process.exit(0);
  } catch (err) {
    console.error('Seed failed:', err.message);
    process.exit(1);
  }
};

seed();
