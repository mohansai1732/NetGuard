const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { db, logAudit } = require('../db');
const config = require('../config');
const { authenticateToken } = require('../middleware/auth');
const { loginLimiter } = require('../middleware/rateLimiter');

// POST /api/auth/login - Rate limited
router.post('/login', loginLimiter, (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  try {
    const userStmt = db.prepare('SELECT * FROM users WHERE username = ?');
    const user = userStmt.get(username.trim());

    if (!user) {
      logAudit('anonymous', 'LOGIN_FAILED', { username, reason: 'User not found' }, 'FAILURE');
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const passwordValid = bcrypt.compareSync(password, user.password_hash);
    if (!passwordValid) {
      logAudit(user.username, 'LOGIN_FAILED', { reason: 'Incorrect password' }, 'FAILURE');
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    // Generate JWT token
    const tokenPayload = {
      id: user.id,
      username: user.username,
      role: user.role
    };

    const token = jwt.sign(tokenPayload, config.jwtSecret, {
      expiresIn: config.jwtExpiresIn
    });

    logAudit(user.username, 'LOGIN_SUCCESS', 'Admin authenticated successfully');

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        mustChangePassword: Boolean(user.must_change_password)
      }
    });
  } catch (err) {
    console.error('[AUTH] Login error:', err);
    res.status(500).json({ error: 'Internal authentication error.' });
  }
});

// POST /api/auth/change-password
router.post('/change-password', authenticateToken, (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!newPassword || newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters long.' });
  }

  try {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found.' });
    }

    // Verify current password
    if (currentPassword) {
      const isMatch = bcrypt.compareSync(currentPassword, user.password_hash);
      if (!isMatch) {
        return res.status(400).json({ error: 'Current password does not match.' });
      }
    }

    const newHash = bcrypt.hashSync(newPassword, 10);
    const updateStmt = db.prepare(`
      UPDATE users 
      SET password_hash = ?, must_change_password = 0, updated_at = CURRENT_TIMESTAMP 
      WHERE id = ?
    `);
    updateStmt.run(newHash, req.user.id);

    logAudit(req.user.username, 'PASSWORD_CHANGE', 'Admin updated their password');

    res.json({
      success: true,
      message: 'Password successfully updated.',
      mustChangePassword: false
    });
  } catch (err) {
    console.error('[AUTH] Change password error:', err);
    res.status(500).json({ error: 'Failed to update password.' });
  }
});

// GET /api/auth/me
router.get('/me', authenticateToken, (req, res) => {
  try {
    const user = db.prepare('SELECT id, username, role, must_change_password, created_at FROM users WHERE id = ?').get(req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found.' });
    }
    res.json({
      id: user.id,
      username: user.username,
      role: user.role,
      mustChangePassword: Boolean(user.must_change_password),
      createdAt: user.created_at
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch user profile.' });
  }
});

module.exports = router;
