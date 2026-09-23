const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../middleware/auth');
const { validateBlocklistInput } = require('../middleware/validator');
const nftablesService = require('../services/nftablesService');

router.use(authenticateToken);

// GET /api/ip-blocklist - Get current list of blocked IPs/subnets
router.get('/', async (req, res) => {
  try {
    const list = await nftablesService.getBlocklist();
    res.json({
      count: list.length,
      blockedIps: list
    });
  } catch (err) {
    console.error('[BLOCKLIST] Error fetching blocklist:', err);
    res.status(500).json({ error: 'Failed to retrieve blocked IPs.' });
  }
});

// POST /api/ip-blocklist - Add IP or subnet to blocklist
router.post('/', validateBlocklistInput, async (req, res) => {
  try {
    const { ip, reason } = req.validatedBlocklist;
    const entry = await nftablesService.addToBlocklist(ip, reason, req.user.username);
    res.status(201).json({
      message: `IP/CIDR ${ip} added to firewall blocklist set.`,
      entry
    });
  } catch (err) {
    if (err.message && err.message.includes('UNIQUE constraint failed')) {
      return res.status(409).json({ error: 'This IP or CIDR is already blocked in the firewall set.' });
    }
    console.error('[BLOCKLIST] Error adding IP to blocklist:', err);
    res.status(500).json({ error: 'Failed to add IP to blocklist.' });
  }
});

// DELETE /api/ip-blocklist/:ip - Remove IP or subnet from blocklist
router.delete('/:ip', async (req, res) => {
  try {
    // Decode in case of CIDR notation like 194.26.29.0%2F24
    const ip = decodeURIComponent(req.params.ip);
    const result = await nftablesService.removeFromBlocklist(ip, req.user.username);
    res.json({
      message: `IP ${ip} removed from firewall blocklist set.`,
      result
    });
  } catch (err) {
    console.error('[BLOCKLIST] Error removing IP from blocklist:', err);
    res.status(500).json({ error: 'Failed to remove IP from blocklist.' });
  }
});

module.exports = router;
