const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../middleware/auth');
const { getRecentConnectionLogs } = require('../db');

// GET /api/logs/recent - real recent connection logs directly from SQLite database
router.get('/recent', authenticateToken, (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 30, 100);
    const logs = getRecentConnectionLogs(limit);
    res.json({
      count: logs.length,
      logs
    });
  } catch (err) {
    console.error('[LOGS] Error retrieving recent connection logs:', err);
    res.status(500).json({ error: 'Failed to retrieve connection logs.' });
  }
});

module.exports = router;
