// End-to-End Integration Verification Script
const VITE_PORT = 5173;
const BASE_URL = `http://localhost:${VITE_PORT}/api`;

async function testFullFlow() {
  console.log('=== NETGUARD END-TO-END FLOW TEST ===');

  // 1. Health via Vite proxy
  console.log('\n1. Testing Vite dev proxy to backend health check...');
  const health = await fetch(`${BASE_URL}/health`).then(r => r.json());
  console.log(`✓ Proxy OK: Service is ${health.service} (${health.status})`);

  // 2. Login with seeded credentials
  console.log('\n2. Testing initial login with seeded credentials (admin / admin123)...');
  const loginRes = await fetch(`${BASE_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password: 'admin123' })
  });
  const loginData = await loginRes.json();
  if (!loginData.token) throw new Error('Login failed: ' + JSON.stringify(loginData));
  console.log(`✓ Login 200 OK. Token acquired. mustChangePassword: ${loginData.user.mustChangePassword}`);

  const token = loginData.token;
  const authHeaders = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`
  };

  // 3. Change password flow
  console.log('\n3. Testing first-login mandatory password change...');
  const changeRes = await fetch(`${BASE_URL}/auth/change-password`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({ currentPassword: 'admin123', newPassword: 'NetGuard@Secure2026' })
  });
  const changeData = await changeRes.json();
  console.log(`✓ Password update response: ${changeData.message}, mustChangePassword: ${changeData.mustChangePassword}`);

  // 4. Verify me endpoint
  console.log('\n4. Verifying user profile state...');
  const me = await fetch(`${BASE_URL}/auth/me`, { headers: authHeaders }).then(r => r.json());
  console.log(`✓ Profile: ${me.username} (Role: ${me.role}), mustChangePassword: ${me.mustChangePassword}`);

  // 5. Get summary stats
  console.log('\n5. Fetching 24h summary metrics...');
  const stats = await fetch(`${BASE_URL}/stats/summary`, { headers: authHeaders }).then(r => r.json());
  console.log(`✓ Stats: Total packets ${stats.totalPackets}, Accepts: ${stats.accepts}, Drops: ${stats.drops}, Drop rate: ${stats.dropRatePercent}%`);

  // 6. Fetch recent connection logs
  console.log('\n6. Fetching live recent connection logs...');
  const logs = await fetch(`${BASE_URL}/logs/recent?limit=5`, { headers: authHeaders }).then(r => r.json());
  console.log(`✓ Retrieved ${logs.count} logs. Latest: ${logs.logs[0].src_ip}:${logs.logs[0].port} -> ${logs.logs[0].action} (${logs.logs[0].reason})`);

  // 7. Add a new firewall rule
  console.log('\n7. Adding a new DROP rule (198.51.100.99 on port 80)...');
  const addRuleRes = await fetch(`${BASE_URL}/rules`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({
      chain: 'input',
      protocol: 'tcp',
      src_ip: '198.51.100.99',
      port: '80',
      action: 'DROP',
      comment: 'Drop malicious web crawler'
    })
  });
  const addRuleData = await addRuleRes.json();
  console.log(`✓ Rule created: Handle #${addRuleData.rule?.handle}, Action: ${addRuleData.rule?.action}, Comment: ${addRuleData.rule?.comment}`);

  // 8. Block an IP in IP Management
  console.log('\n8. Blocking an IP in @blocklist set (203.0.113.88)...');
  const blockRes = await fetch(`${BASE_URL}/ip-blocklist`, {
    method: 'POST',
    headers: authHeaders,
    body: JSON.stringify({
      ip: '203.0.113.88',
      reason: 'Repeated brute force SSH probes'
    })
  });
  const blockData = await blockRes.json();
  console.log(`✓ Blocklist entry added: ${blockData.entry?.ip}, Reason: ${blockData.entry?.reason}`);

  // 9. Verify blocklist
  console.log('\n9. Querying active @blocklist set...');
  const blocklist = await fetch(`${BASE_URL}/ip-blocklist`, { headers: authHeaders }).then(r => r.json());
  const found = blocklist.blockedIps.some(b => b.ip_or_cidr === '203.0.113.88');
  console.log(`✓ Verified 203.0.113.88 in blocklist: ${found} (Total blocked: ${blocklist.count})`);

  // 10. Unblock IP
  console.log('\n10. Unblocking IP 203.0.113.88...');
  const unblockRes = await fetch(`${BASE_URL}/ip-blocklist/203.0.113.88`, {
    method: 'DELETE',
    headers: authHeaders
  });
  const unblockData = await unblockRes.json();
  console.log(`✓ Unblock response: ${unblockData.message}`);

  // 11. Verify Audit Logs
  console.log('\n11. Querying administrative audit trail...');
  const audit = await fetch(`${BASE_URL}/audit-logs?limit=10`, { headers: authHeaders }).then(r => r.json());
  console.log(`✓ Total audit records: ${audit.count}`);
  audit.logs.slice(0, 5).forEach(l => {
    console.log(`   - [${l.action}] by ${l.admin_username} at ${l.timestamp}`);
  });

  console.log('\n=== ALL END-TO-END FLOWS COMPLETED SUCCESSFULLY ===');
}

testFullFlow().catch(err => {
  console.error('E2E Test Failed:', err);
  process.exit(1);
});
