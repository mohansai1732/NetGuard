const http = require('http');
const express = require('express');
const cors = require('cors');
const config = require('./config');
const { initDatabase } = require('./db');
const { apiLimiter } = require('./middleware/rateLimiter');
const { initWebSocket } = require('./services/websocketService');

// Route modules
const authRoutes = require('./routes/auth');
const statsRoutes = require('./routes/stats');
const logsRoutes = require('./routes/logs');
const rulesRoutes = require('./routes/rules');
const ipBlocklistRoutes = require('./routes/ipBlocklist');
const auditLogsRoutes = require('./routes/auditLogs');

// 1. Initialize SQLite Database & seed admin user
initDatabase();

// 2. Initialize Express application
const app = express();

// Security and utility middleware
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json());

// Global API rate limiting
app.use('/api/', apiLimiter);

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    service: 'NetGuard Firewall Daemon Interface',
    version: '1.0.0',
    mode: 'MOCK_NFTABLES',
    timestamp: new Date().toISOString()
  });
});

// Mount modular API routers
app.use('/api/auth', authRoutes);
app.use('/api/stats', statsRoutes);
app.use('/api/logs', logsRoutes);
app.use('/api/rules', rulesRoutes);
app.use('/api/ip-blocklist', ipBlocklistRoutes);
app.use('/api/audit-logs', auditLogsRoutes);

// 404 Handler for undefined API routes
app.use('/api/*', (req, res) => {
  res.status(404).json({ error: `Route ${req.originalUrl} not found.` });
});

// Centralized error handler
app.use((err, req, res, next) => {
  console.error('[SERVER ERROR]', err);
  res.status(err.status || 500).json({
    error: config.isProduction ? 'An unexpected server error occurred.' : err.message
  });
});

// 3. Create HTTP Server and bind Authenticated WebSocket Server
const server = http.createServer(app);
initWebSocket(server);

// Start listening
server.listen(config.port, () => {
  console.log('\x1b[32m%s\x1b[0m', '════════════════════════════════════════════════════════════');
  console.log('\x1b[32m%s\x1b[0m', `  🛡️  NetGuard Backend Daemon running on port ${config.port}`);
  console.log('\x1b[36m%s\x1b[0m', `  ⚡ REST API:  http://localhost:${config.port}/api`);
  console.log('\x1b[36m%s\x1b[0m', `  📡 WebSocket: ws://localhost:${config.port}/ws (Auth Required)`);
  console.log('\x1b[32m%s\x1b[0m', '════════════════════════════════════════════════════════════');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('Received SIGTERM. Shutting down NetGuard daemon...');
  server.close(() => process.exit(0));
});
