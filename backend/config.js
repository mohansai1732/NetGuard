const crypto = require('crypto');
const path = require('path');

const isProduction = process.env.NODE_ENV === 'production';
let jwtSecret = process.env.JWT_SECRET;

if (!jwtSecret) {
  if (isProduction) {
    console.error('CRITICAL SECURITY ERROR: JWT_SECRET environment variable is missing in production mode!');
    console.error('NetGuard will refuse to boot without an explicit JWT_SECRET set.');
    process.exit(1);
  } else {
    // Generate a secure ephemeral secret for development
    jwtSecret = crypto.randomBytes(32).toString('hex');
    console.warn('\x1b[33m%s\x1b[0m', '─────────────────────────────────────────────────────────────');
    console.warn('\x1b[33m%s\x1b[0m', '[SECURITY WARNING] No JWT_SECRET provided in development mode.');
    console.warn('\x1b[33m%s\x1b[0m', 'Using auto-generated ephemeral secret. Note: Server restarts');
    console.warn('\x1b[33m%s\x1b[0m', 'will invalidate all active login sessions.');
    console.warn('\x1b[33m%s\x1b[0m', '─────────────────────────────────────────────────────────────');
  }
}

module.exports = {
  port: parseInt(process.env.PORT, 10) || 5000,
  isProduction,
  jwtSecret,
  jwtExpiresIn: '12h',
  dbPath: path.resolve(__dirname, 'data', 'netguard.db'),
  allowedChains: ['input', 'forward'],
  defaultChains: ['input', 'forward', 'output']
};
