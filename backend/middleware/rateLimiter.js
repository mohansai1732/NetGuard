const { rateLimit } = require('express-rate-limit');

// Global API rate limiter: 120 requests per 1 minute
const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  limit: 120,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: {
    error: 'Too many requests. Please slow down and try again shortly.'
  }
});

// Dedicated login brute-force limiter: 5 failed attempts per 15 minutes
// NOTE: We key by IP + username so that in shared NAT environments, failed attempts
// for one username won't lock out other legitimate accounts behind the same gateway.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  skipSuccessfulRequests: true, // Only count failed attempts against the limit
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  keyGenerator: (req) => {
    // Key by IP and target username (or fallback to IP if body unavailable)
    const username = req.body && req.body.username ? String(req.body.username).toLowerCase().trim() : '';
    return `${req.ip}_${username}`;
  },
  message: {
    error: 'Too many failed login attempts for this account. Please wait 15 minutes before trying again.'
  }
});

module.exports = {
  apiLimiter,
  loginLimiter
};
