const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../middleware/auth');
const { db } = require('../db');

router.use(authenticateToken);

// GET /api/audit-logs - Full audit trail of firewall modifications
router.get('/', (req, res) => {
  try {
    const { action, admin, search, limit = 50 } = req.query;
    const maxLimit = Math.min(parseInt(limit, 10) || 50, 200);

    let query = 'SELECT id, admin_username, action, details, status, timestamp FROM audit_logs WHERE 1=1';
    const params = [];

    if (action && action !== 'ALL') {
      query += ' AND action = ?';
      params.push(action);
    }

    if (admin && admin !== 'ALL') {
      query += ' AND admin_username = ?';
      params.push(admin);
    }

    if (search) {
      query += ' AND (details LIKE ? OR action LIKE ?)';
      params.push(`%${search}%`, `%${search}%`);
    }

    query += ' ORDER BY id DESC LIMIT ?';
    params.push(maxLimit);

    const stmt = db.prepare(query);
    const logs = stmt.all(...params);

    res.json({
      count: logs.length,
      logs: logs.map(log => {
        let parsedDetails = log.details;
        try {
          parsedDetails = JSON.parse(log.details);
        } catch (e) {
          // keep as string
        }
        return {
          ...log,
          details: parsedDetails
        };
      })
    });
  } catch (err) {
    console.error('[AUDIT] Error fetching audit logs:', err);
    res.status(500).json({ error: 'Failed to retrieve audit logs.' });
  }
});

module.exports = router;
