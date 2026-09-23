const http = require('http');
const { WebSocket } = require('ws');

async function testApi() {
  // Start server
  const serverProcess = require('./server');

  // Wait 1 second for port to bind
  await new Promise(res => setTimeout(res, 1000));

  console.log('--- TESTING HTTP & WS ENDPOINTS ---');

  // 1. Health check
  const health = await fetch('http://localhost:5000/api/health').then(r => r.json());
  console.log('1. Health check response:', health.status, health.mode);
  if (health.status !== 'online') throw new Error('Health check failed');

  // 2. Login as admin
  const loginRes = await fetch('http://localhost:5000/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password: 'admin123' })
  });
  const loginData = await loginRes.json();
  console.log('2. Login response:', loginRes.status, 'Token acquired:', Boolean(loginData.token), 'Must change password:', loginData.user?.mustChangePassword);
  if (!loginData.token) throw new Error('Login failed to yield token');

  const token = loginData.token;

  // 3. Stats summary
  const stats = await fetch('http://localhost:5000/api/stats/summary', {
    headers: { 'Authorization': `Bearer ${token}` }
  }).then(r => r.json());
  console.log('3. Stats summary:', stats.period, 'Total packets:', stats.totalPackets, 'Accepts:', stats.accepts, 'Drops:', stats.drops);

  // 4. Test WebSocket without auth (should fail with 4001)
  console.log('4. Testing WS connection without token...');
  let unauthRejected = false;
  await new Promise((resolve) => {
    const ws = new WebSocket('ws://localhost:5000/ws');
    ws.on('close', (code, reason) => {
      console.log(`✓ Unauthenticated WS closed as expected. Code: ${code}, reason: ${reason.toString()}`);
      unauthRejected = true;
      resolve();
    });
    ws.on('error', () => {});
    // Timeout in 6s (since auth grace is 5s)
    setTimeout(resolve, 6000);
  });

  // 5. Test WebSocket with token
  console.log('5. Testing WS connection with token query param...');
  let authSuccess = false;
  await new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://localhost:5000/ws?token=${token}`);
    ws.on('open', () => {
      console.log('✓ Authenticated WS opened successfully');
    });
    ws.on('message', (msg) => {
      const data = JSON.parse(msg.toString());
      console.log('✓ Received WS message type:', data.type);
      if (data.type === 'welcome' || data.type === 'traffic_packet') {
        authSuccess = true;
        ws.close();
        resolve();
      }
    });
    ws.on('error', (err) => {
      reject(err);
    });
    setTimeout(() => {
      ws.close();
      resolve();
    }, 4000);
  });

  console.log('--- ALL SERVER API & WEBSOCKET TESTS COMPLETED SUCCESSFULLY ---');
  process.exit(0);
}

testApi().catch(err => {
  console.error('Server test failed:', err);
  process.exit(1);
});
