const config = require('../config');

// Regular expressions for IPv4 and IPv6 with optional CIDR prefix
const IPV4_CIDR_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/(?:[0-9]|[12][0-9]|3[0-2]))?$/;
const IPV6_CIDR_REGEX = /^(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}(?:\/(?:[0-9]|[1-9][0-9]|1[01][0-9]|12[0-8]))?$/;

const VALID_PROTOCOLS = ['tcp', 'udp', 'icmp', 'any'];
const VALID_ACTIONS = ['ACCEPT', 'DROP', 'REJECT'];

function isValidIpOrCidr(str) {
  if (!str || typeof str !== 'string') return false;
  const trimmed = str.trim();
  return IPV4_CIDR_REGEX.test(trimmed) || IPV6_CIDR_REGEX.test(trimmed);
}

function isValidPort(port) {
  if (port === undefined || port === null || port === '' || port === 'any') return true;
  const num = parseInt(port, 10);
  if (isNaN(num)) {
    // Check if it's a range like "80-443"
    if (typeof port === 'string' && /^\d+-\d+$/.test(port)) {
      const [start, end] = port.split('-').map(Number);
      return start >= 1 && end <= 65535 && start <= end;
    }
    return false;
  }
  return num >= 1 && num <= 65535;
}

function validateRuleInput(req, res, next) {
  const { chain, protocol, src_ip, dst_ip, port, action } = req.body;

  // 1. Strict Chain Scoping
  if (!chain || !config.allowedChains.includes(chain)) {
    return res.status(400).json({
      error: `Invalid chain '${chain}'. For security, rule modifications are strictly scoped to: ${config.allowedChains.join(', ')}`
    });
  }

  // 2. Protocol validation
  const proto = (protocol || 'any').toLowerCase();
  if (!VALID_PROTOCOLS.includes(proto)) {
    return res.status(400).json({
      error: `Invalid protocol '${protocol}'. Supported protocols: ${VALID_PROTOCOLS.join(', ')}`
    });
  }

  // 3. Source IP validation (optional, but if provided must be valid)
  if (src_ip && src_ip !== 'any' && !isValidIpOrCidr(src_ip)) {
    return res.status(400).json({
      error: `Invalid Source IP/CIDR '${src_ip}'. Must be a valid IPv4 or IPv6 address/subnet.`
    });
  }

  // 4. Destination IP validation (optional)
  if (dst_ip && dst_ip !== 'any' && !isValidIpOrCidr(dst_ip)) {
    return res.status(400).json({
      error: `Invalid Destination IP/CIDR '${dst_ip}'. Must be a valid IPv4 or IPv6 address/subnet.`
    });
  }

  // 5. Port validation
  if (!isValidPort(port)) {
    return res.status(400).json({
      error: `Invalid port '${port}'. Must be an integer between 1 and 65535, a range (e.g. 80-443), or 'any'.`
    });
  }

  // 6. Action validation
  if (!action || !VALID_ACTIONS.includes(action.toUpperCase())) {
    return res.status(400).json({
      error: `Invalid action '${action}'. Allowed actions: ${VALID_ACTIONS.join(', ')}`
    });
  }

  // Clean inputs attached to req.validatedRule
  req.validatedRule = {
    chain,
    protocol: proto,
    src_ip: (src_ip && src_ip !== 'any') ? src_ip.trim() : null,
    dst_ip: (dst_ip && dst_ip !== 'any') ? dst_ip.trim() : null,
    port: (port && port !== 'any') ? String(port).trim() : null,
    action: action.toUpperCase()
  };

  next();
}

function validateBlocklistInput(req, res, next) {
  const { ip, reason } = req.body;

  if (!ip || !isValidIpOrCidr(ip)) {
    return res.status(400).json({
      error: 'A valid IPv4 or IPv6 address or CIDR subnet is required.'
    });
  }

  req.validatedBlocklist = {
    ip: ip.trim(),
    reason: (reason && typeof reason === 'string') ? reason.trim().slice(0, 255) : 'Manually blocked via NetGuard'
  };

  next();
}

module.exports = {
  isValidIpOrCidr,
  isValidPort,
  validateRuleInput,
  validateBlocklistInput
};
