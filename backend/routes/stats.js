const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../middleware/auth');
const { getRealStats } = require('../db');
const systemStatus = require('../services/systemStatus');
const { getActiveClientCount } = require('../services/websocketService');

// GET /api/stats/summary - Real SQLite metrics, host availability, and active socket connections
router.get('/summary', authenticateToken, (req, res) => {
  try {
    const realStats = getRealStats();
    const status = systemStatus.getStatus();

    res.json({
      available: status.available,
      systemStatus: status,
      totalPackets: realStats.totalPackets,
      accepts: realStats.accepts,
      drops: realStats.drops,
      rejects: realStats.rejects,
      dropRatePercent: realStats.dropRatePercent,
      packetRate: realStats.packetRate,
      activeClients: getActiveClientCount(),
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('[STATS] Error fetching summary:', err);
    res.status(500).json({ error: 'Failed to retrieve stats summary.' });
  }
});

// GET /api/stats/system - Single source of truth for host platform & nftables capabilities
router.get('/system', authenticateToken, (req, res) => {
  try {
    res.json(systemStatus.getStatus());
  } catch (err) {
    res.status(500).json({ error: 'Failed to retrieve system status.' });
  }
});

module.exports = router;
