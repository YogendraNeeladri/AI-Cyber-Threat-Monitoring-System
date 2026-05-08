const jwt = require('jsonwebtoken');
const User = require('../models/User');
const logger = require('../utils/logger');

const JWT_SECRET = process.env.JWT_SECRET || 'cyber_threat_jwt_super_secret_key_2024';
const JWT_EXPIRES = process.env.JWT_EXPIRES_IN || '8h';
const REFRESH_SECRET = process.env.REFRESH_TOKEN_SECRET || 'cyber_refresh_secret_2024';
const REFRESH_EXPIRES = '7d';

const generateTokens = (userId, role) => {
  const accessToken = jwt.sign({ id: userId, role }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
  const refreshToken = jwt.sign({ id: userId }, REFRESH_SECRET, { expiresIn: REFRESH_EXPIRES });
  return { accessToken, refreshToken };
};

// ─── POST /api/auth/register ───────────────────────────────────────────────
const register = async (req, res) => {
  try {
    const { name, email, password, role = 'viewer' } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email and password are required' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ error: 'User with this email already exists' });
    }

    const user = await User.create({ name, email, password, role });
    const { accessToken, refreshToken } = generateTokens(user._id, user.role);

    await User.findByIdAndUpdate(user._id, { refreshToken });

    logger.info(`New user registered: ${email} | Role: ${role}`);

    return res.status(201).json({
      success: true,
      user: { _id: user._id, name, email, role },
      accessToken,
      refreshToken,
    });
  } catch (err) {
    logger.error(`register error: ${err.message}`);
    return res.status(500).json({ error: 'Registration failed' });
  }
};

// ─── POST /api/auth/login ──────────────────────────────────────────────────
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await User.findOne({ email }).select('+password');
    if (!user || !(await user.matchPassword(password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (!user.isActive) {
      return res.status(403).json({ error: 'Account deactivated. Contact administrator.' });
    }

    const { accessToken, refreshToken } = generateTokens(user._id, user.role);

    await User.findByIdAndUpdate(user._id, {
      refreshToken,
      lastLogin: new Date(),
      $inc: { loginCount: 1 },
    });

    logger.info(`User logged in: ${email}`);

    return res.json({
      success: true,
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        preferences: user.preferences,
      },
      accessToken,
      refreshToken,
    });
  } catch (err) {
    logger.error(`login error: ${err.message}`);
    return res.status(500).json({ error: 'Login failed' });
  }
};

// ─── POST /api/auth/refresh ────────────────────────────────────────────────
const refresh = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(401).json({ error: 'Refresh token required' });

    const decoded = jwt.verify(refreshToken, REFRESH_SECRET);
    const user = await User.findById(decoded.id).select('+refreshToken');

    if (!user || user.refreshToken !== refreshToken) {
      return res.status(403).json({ error: 'Invalid refresh token' });
    }

    const tokens = generateTokens(user._id, user.role);
    await User.findByIdAndUpdate(user._id, { refreshToken: tokens.refreshToken });

    return res.json({ success: true, ...tokens });
  } catch (err) {
    return res.status(403).json({ error: 'Refresh token expired or invalid' });
  }
};

// ─── POST /api/auth/logout ─────────────────────────────────────────────────
const logout = async (req, res) => {
  try {
    if (req.user) {
      await User.findByIdAndUpdate(req.user._id, { refreshToken: null });
    }
    return res.json({ success: true, message: 'Logged out successfully' });
  } catch (err) {
    return res.status(500).json({ error: 'Logout failed' });
  }
};

// ─── GET /api/auth/me ──────────────────────────────────────────────────────
const getMe = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    return res.json({ success: true, user });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to get user' });
  }
};

module.exports = { register, login, refresh, logout, getMe };
