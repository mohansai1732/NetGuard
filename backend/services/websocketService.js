const { WebSocketServer } = require('ws');
const { verifyWsToken } = require('../middleware/auth');
const kernelLogService = require('./kernelLogService');
const systemStatus = require('./systemStatus');

let wss = null;

function initWebSocket(server) {
  wss = new WebSocketServer({ noServer: true });

  // Handle HTTP upgrade with authentication verification
  server.on('upgrade', (request, socket, head) => {
    const parsedUrl = new URL(request.url, `http://${request.headers.host || 'localhost'}`);

    if (parsedUrl.pathname !== '/ws') {
      socket.destroy();
      return;
    }

    // Check token from query parameter: ws://.../ws?token=<jwt>
    const token = parsedUrl.searchParams.get('token');
    const user = verifyWsToken(token);

    // If token provided in query and valid -> proceed immediately
    if (user) {
      wss.handleUpgrade(request, socket, head, (ws) => {
        ws.user = user;
        ws.isAuthenticated = true;
        wss.emit('connection', ws, request);
      });
      return;
    }

    // Support handshake auth ticket / initial message auth:
    // If no query token, upgrade socket temporarily with 5s auth grace period
    wss.handleUpgrade(request, socket, head, (ws) => {
      ws.isAuthenticated = false;
      ws.authTimeout = setTimeout(() => {
        if (!ws.isAuthenticated) {
          console.warn('[WS] Closing unauthenticated connection (auth timeout)');
          ws.close(4001, 'Unauthorized: Missing or invalid token');
        }
      }, 5000);
      wss.emit('connection', ws, request);
    });
  });

  wss.on('connection', (ws, req) => {
    // If not authenticated via query param, expect initial { type: 'auth', token: '...' } message
    if (!ws.isAuthenticated) {
      ws.send(JSON.stringify({
        type: 'auth_required',
        message: 'Please send authentication message: {"type":"auth","token":"<jwt>"}'
      }));
    } else {
      ws.send(JSON.stringify({
        type: 'welcome',
        message: 'Connected to NetGuard Live Event Feed (Authenticated)',
        user: ws.user.username,
        systemStatus: systemStatus.getStatus()
      }));
    }

    ws.on('message', (message) => {
      try {
        const data = JSON.parse(message.toString());

        if (data.type === 'auth') {
          const user = verifyWsToken(data.token);
          if (user) {
            ws.user = user;
            ws.isAuthenticated = true;
            if (ws.authTimeout) clearTimeout(ws.authTimeout);
            ws.send(JSON.stringify({
              type: 'auth_success',
              message: 'Authentication successful',
              user: user.username,
              systemStatus: systemStatus.getStatus()
            }));
          } else {
            ws.close(4001, 'Unauthorized: Invalid token');
          }
        } else if (data.type === 'ping') {
          ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
        }
      } catch (err) {
        // Ignore malformed client messages
      }
    });

    ws.on('close', () => {
      if (ws.authTimeout) clearTimeout(ws.authTimeout);
    });

    ws.on('error', (err) => {
      console.error('[WS] Client error:', err.message);
    });
  });

  // Wire real kernel log events to all authenticated clients
  kernelLogService.onPacket((packet) => {
    if (!wss) return;
    const message = JSON.stringify({
      type: 'traffic_packet',
      packet
    });

    wss.clients.forEach((client) => {
      if (client.readyState === 1 && client.isAuthenticated) {
        client.send(message);
      }
    });
  });

  console.log('[WS] Authenticated WebSocket server initialized on /ws');
  return wss;
}

function getActiveClientCount() {
  if (!wss) return 0;
  let count = 0;
  wss.clients.forEach((c) => {
    if (c.readyState === 1 && c.isAuthenticated) count++;
  });
  return count;
}

module.exports = {
  initWebSocket,
  getActiveClientCount
};
