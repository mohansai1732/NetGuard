const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../middleware/auth');
const { validateRuleInput } = require('../middleware/validator');
const nftablesService = require('../services/nftablesService');

// All rule operations require authentication
router.use(authenticateToken);

// GET /api/rules - List current ruleset
router.get('/', async (req, res) => {
  try {
    const ruleset = await nftablesService.listRuleset();
    res.json(ruleset);
  } catch (err) {
    console.error('[RULES] Error listing rules:', err);
    res.status(500).json({ error: 'Failed to retrieve ruleset from nftables.' });
  }
});

// POST /api/rules - Add new rule (strictly validated and built server-side)
router.post('/', validateRuleInput, async (req, res) => {
  try {
    const createdRule = await nftablesService.addRule(req.validatedRule, req.user.username);
    res.status(201).json({
      message: 'Rule successfully created and applied.',
      rule: createdRule
    });
  } catch (err) {
    console.error('[RULES] Error adding rule:', err);
    res.status(500).json({ error: err.message || 'Failed to create firewall rule.' });
  }
});

// PUT /api/rules/:handle - Edit existing rule
router.put('/:handle', validateRuleInput, async (req, res) => {
  try {
    const updatedRule = await nftablesService.updateRule(req.params.handle, req.validatedRule, req.user.username);
    res.json({
      message: `Rule #${req.params.handle} successfully updated.`,
      rule: updatedRule
    });
  } catch (err) {
    console.error('[RULES] Error updating rule:', err);
    res.status(404).json({ error: err.message || 'Rule not found.' });
  }
});

// DELETE /api/rules/:handle - Delete rule by handle
router.delete('/:handle', async (req, res) => {
  try {
    const result = await nftablesService.deleteRule(req.params.handle, req.user.username);
    res.json({
      message: `Rule #${req.params.handle} successfully deleted.`,
      result
    });
  } catch (err) {
    console.error('[RULES] Error deleting rule:', err);
    res.status(404).json({ error: err.message || 'Rule not found.' });
  }
});

module.exports = router;
