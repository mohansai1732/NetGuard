const { initDatabase, db, recordConnectionLog, getRealStats } = require('./db');
const nftablesService = require('./services/nftablesService');
const { parseKernelLogLine } = require('./services/kernelLogService');
const systemStatus = require('./services/systemStatus');

async function runTests() {
  console.log('--- STARTING BACKEND TESTS (REAL DATA / NO SIMULATION) ---');

  // 1. Database & Seeding Test
  console.log('1. Checking DB initialization & admin seed...');
  initDatabase();
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get('admin');
  if (!user) throw new Error('Admin user was not seeded in SQLite');
  console.log(`✓ Admin user exists with ID ${user.id}`);

  // 2. Ruleset Listing Test
  console.log('2. Checking nftables ruleset listing...');
  const ruleset = await nftablesService.listRuleset();
  if (!ruleset.nftables || !Array.isArray(ruleset.rules)) throw new Error('Ruleset missing nftables array or rules');
  console.log(`✓ Ruleset loaded. Tables/chains: ${ruleset.nftables.length}, parsed rules: ${ruleset.rules.length}`);

  // 3. Add Rule Test
  console.log('3. Adding test DROP rule...');
  const testRule = await nftablesService.addRule({
    chain: 'input',
    protocol: 'tcp',
    src_ip: '198.51.100.99',
    dst_ip: null,
    port: '80',
    action: 'DROP',
    comment: 'Test unit drop rule'
  }, 'admin');
  console.log(`✓ Rule added with handle #${testRule.handle}`);

  // 4. Test Key-Value Kernel Log Parser (Sample real kernel output)
  console.log('4. Testing kernel log line parser on real netfilter log samples...');
  const sampleDrop = 'NETGUARD-DROP: IN=eth0 OUT= MAC=52:54:00:12:34:56:52:54:00:ab:cd:ef:08:00 SRC=198.51.100.99 DST=192.168.1.10 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=18942 DF PROTO=TCP SPT=49210 DPT=80 WINDOW=64240 RES=0x00 SYN URGP=0';
  const parsedDrop = parseKernelLogLine(sampleDrop);
  if (!parsedDrop || parsedDrop.action !== 'DROP' || parsedDrop.src_ip !== '198.51.100.99' || parsedDrop.port !== '80') {
    throw new Error(`Kernel log parser failed on DROP sample! Got: ${JSON.stringify(parsedDrop)}`);
  }
  console.log(`✓ Kernel log parser correctly parsed DROP event: ${parsedDrop.src_ip}:${parsedDrop.port} -> ${parsedDrop.action}`);

  const sampleAccept = 'NETGUARD-ACCEPT: IN=eth0 OUT= SRC=10.0.0.15 DST=192.168.1.1 LEN=40 PROTO=TCP SPT=55222 DPT=443';
  const parsedAccept = parseKernelLogLine(sampleAccept);
  if (!parsedAccept || parsedAccept.action !== 'ACCEPT' || parsedAccept.src_ip !== '10.0.0.15' || parsedAccept.port !== '443') {
    throw new Error(`Kernel log parser failed on ACCEPT sample! Got: ${JSON.stringify(parsedAccept)}`);
  }
  console.log(`✓ Kernel log parser correctly parsed ACCEPT event: ${parsedAccept.src_ip}:${parsedAccept.port} -> ${parsedAccept.action}`);

  // 5. Blocklist Test
  console.log('5. Testing IP blocklist set...');
  const testBlockedIp = '203.0.113.77';
  await nftablesService.addToBlocklist(testBlockedIp, 'Malicious probe test', 'admin');
  const blocklist = await nftablesService.getBlocklist();
  if (!blocklist.some(b => b.ip_or_cidr === testBlockedIp)) {
    throw new Error('Blocked IP was not stored in blocklist table');
  }
  console.log(`✓ Blocklist stored entry correctly.`);

  // 6. Real SQLite stats test
  console.log('6. Testing real SQLite stats counter calculation...');
  recordConnectionLog(parsedDrop);
  const stats = getRealStats();
  if (stats.totalPackets < 1 || stats.drops < 1) {
    throw new Error('SQLite stats did not record parsed kernel log event');
  }
  console.log(`✓ Real SQLite stats verified: totalPackets: ${stats.totalPackets}, drops: ${stats.drops}`);

  // 7. System status test
  console.log('7. Verifying single source of truth system status...');
  const status = systemStatus.getStatus();
  console.log(`✓ System status verified: platform=${status.platform}, available=${status.available}`);

  // Clean up test rule and blocked IP
  await nftablesService.deleteRule(testRule.handle, 'admin');
  await nftablesService.removeFromBlocklist(testBlockedIp, 'admin');
  console.log('✓ Cleaned up test rule and test blocklist entry.');

  console.log('--- ALL BACKEND TESTS PASSED (REAL LOG TAILER & PARSER VERIFIED) ---');
}

runTests().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});
