const jwt = require('jsonwebtoken');
const User = require('../models/User');

const JWT_SECRET = process.env.JWT_SECRET || 'cyber_threat_jwt_super_secret_key_2024';

const socketAuth = async (socket, next) => {
  const token =
    socket.handshake.auth?.token ||
    socket.handshake.headers?.authorization?.replace('Bearer ', '');

  if (!token) {
    // Allow viewer connections without auth (read-only dashboard)
    socket.user = { role: 'viewer', name: 'Anonymous' };
    return next();
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.id).select('name email role isActive');
    if (!user || !user.isActive) {
      socket.user = { role: 'viewer', name: 'Anonymous' };
    } else {
      socket.user = user;
    }
    next();
  } catch {
    socket.user = { role: 'viewer', name: 'Anonymous' };
    next();
  }
};

module.exports = { socketAuth };
