const assert = require('assert');
const { Firewall, ipInCidr, portMatches } = require('./firewall');

function runTests() {
  console.log('\n=============================================================');
  console.log('🛡️   NETGUARD - DYNAMIC FIREWALL ENGINE TEST SUITE');
  console.log('=============================================================\n');

  const fw = new Firewall();

  // 1. Bitwise CIDR matching
  console.log('1. Testing bitwise CIDR subnet matching math...');
  assert.strictEqual(ipInCidr('194.26.29.105', '194.26.29.0/24'), true, 'Should match IP in /24 subnet');
  assert.strictEqual(ipInCidr('194.26.30.1', '194.26.29.0/24'), false, 'Should not match IP outside /24 subnet');
  assert.strictEqual(ipInCidr('10.15.2.1', '10.0.0.0/8'), true, 'Should match IP in /8 subnet');
  assert.strictEqual(ipInCidr('11.0.0.1', '10.0.0.0/8'), false, 'Should not match IP outside /8 subnet');
  assert.strictEqual(ipInCidr('192.168.1.5', '192.168.1.5'), true, 'Should match exact IP');
  assert.strictEqual(ipInCidr('192.168.1.6', '192.168.1.5'), false, 'Should reject mismatched exact IP');
  assert.strictEqual(ipInCidr('8.8.8.8', '0.0.0.0/0'), true, 'Should match any IP for 0.0.0.0/0');
  console.log('  ✓ Bitwise CIDR matching passed');

  // 2. Port Matching Logic (Single, Comma List, Port Ranges)
  console.log('2. Testing port matching rules...');
  assert.strictEqual(portMatches('80', '80'), true, 'Single port exact match');
  assert.strictEqual(portMatches('443', '80'), false, 'Single port mismatch');
  assert.strictEqual(portMatches('443', '80, 443, 8080'), true, 'Port list match');
  assert.strictEqual(portMatches('22', '80, 443, 8080'), false, 'Port list mismatch');
  assert.strictEqual(portMatches('8050', '8000-8090'), true, 'Port range match');
  assert.strictEqual(portMatches('9000', '8000-8090'), false, 'Port range mismatch');
  assert.strictEqual(portMatches(null, '80'), false, 'Null port should not match specific port');
  assert.strictEqual(portMatches('80', null), true, 'Rule with null port matches any port');
  console.log('  ✓ Port matching logic passed');

  // 3. Dynamic Rule Testing from rules.json
  console.log('3. Dynamically testing active rules from rules.json...');
  const rules = fw.getRules();
  assert(Array.isArray(rules) && rules.length > 0, 'rules.json must contain at least one active rule');

  let dynamicRuleMatches = 0;
  for (const rule of rules) {
    // Generate a packet that precisely matches this rule's criteria
    let testIp = '198.51.100.200';
    if (rule.src_ip && rule.src_ip !== 'any' && rule.src_ip !== '0.0.0.0/0') {
      if (rule.src_ip.includes('/')) {
        const netBase = rule.src_ip.split('/')[0];
        const octets = netBase.split('.');
        octets[3] = '15'; // Pick host .15 inside network
        testIp = octets.join('.');
      } else {
        testIp = rule.src_ip;
      }
    }

    const testPacket = {
      ip: testIp,
      chain: rule.chain || 'input',
      protocol: (rule.protocol && rule.protocol !== 'any') ? rule.protocol.toUpperCase() : 'TCP',
      port: rule.port != null ? String(rule.port).split(',')[0].trim() : null
    };

    const res = fw.executePacket(testPacket);
    assert.strictEqual(res.action, rule.action.toUpperCase(), `Rule #${rule.handle} action mismatch`);
    assert.strictEqual(res.matched_rule_handle, rule.handle, `Rule #${rule.handle} handle mismatch`);
    dynamicRuleMatches++;
    console.log(`  ✓ Rule #${rule.handle} [${rule.chain}] [${rule.protocol || 'any'}] port:${rule.port || 'any'} -> yielded ${res.action} (${rule.comment})`);
  }
  console.log(`  ✓ All ${dynamicRuleMatches} active rules in rules.json dynamically verified`);

  // 4. Dynamic Blocklist Testing from blocklist.json
  console.log('4. Dynamically testing active blocklist from blocklist.json...');
  const blocklist = fw.getBlocklist();
  assert(Array.isArray(blocklist) && blocklist.length > 0, 'blocklist.json must contain entries');

  let dynamicBlockMatches = 0;
  for (const entry of blocklist) {
    let testIp = entry.ip_or_cidr;
    if (entry.ip_or_cidr.includes('/')) {
      const netBase = entry.ip_or_cidr.split('/')[0];
      const octets = netBase.split('.');
      octets[3] = '99';
      testIp = octets.join('.');
    }

    const testPacket = { ip: testIp, port: 80, protocol: 'TCP', chain: 'input' };
    const res = fw.executePacket(testPacket);
    assert.strictEqual(res.action, 'DROP', `Blocklist entry ${entry.ip_or_cidr} should result in DROP`);
    assert.strictEqual(res.matched_set, '@blocklist', `Blocklist entry ${entry.ip_or_cidr} should match @blocklist set`);
    dynamicBlockMatches++;
    console.log(`  ✓ Blocklist '${entry.ip_or_cidr}' -> correctly DROPPED (${entry.reason})`);
  }
  console.log(`  ✓ All ${dynamicBlockMatches} blocklist entries verified`);

  // 5. Default Chain Policy Fallthrough
  console.log('5. Testing default chain policy fallthrough...');
  const unmatchedInput = fw.executePacket({ ip: '203.0.113.250', port: 65432, protocol: 'TCP', chain: 'input' });
  assert.strictEqual(unmatchedInput.action, 'ACCEPT', 'Default input chain policy should be ACCEPT');
  assert.strictEqual(unmatchedInput.matched_rule_handle, null, 'Unmatched packet should have null rule handle');

  const unmatchedForward = fw.executePacket({ ip: '172.31.255.1', port: 9000, protocol: 'TCP', chain: 'forward' });
  assert.strictEqual(unmatchedForward.action, 'DROP', 'Default forward chain policy should be DROP');
  assert.strictEqual(unmatchedForward.matched_rule_handle, null, 'Unmatched forward should have null rule handle');
  console.log('  ✓ Default chain policies verified (input -> ACCEPT, forward -> DROP)');

  // 6. Dynamic Rule CRUD Test (Add -> Evaluate -> Delete -> Verify Fallthrough)
  console.log('6. Testing dynamic rule lifecycle (Add, Execute, Delete)...');
  const tempRule = fw.addRule({
    chain: 'input',
    protocol: 'tcp',
    port: '9999',
    action: 'REJECT',
    comment: 'Temporary dynamic test rule'
  });
  const tempRes = fw.executePacket({ ip: '192.168.1.20', port: 9999, protocol: 'TCP', chain: 'input' });
  assert.strictEqual(tempRes.action, 'REJECT');
  assert.strictEqual(tempRes.matched_rule_handle, tempRule.handle);
  console.log(`  ✓ Dynamic rule #${tempRule.handle} added and correctly evaluated to REJECT`);

  fw.deleteRule(tempRule.handle);
  const afterDeleteRes = fw.executePacket({ ip: '192.168.1.20', port: 9999, protocol: 'TCP', chain: 'input' });
  assert.strictEqual(afterDeleteRes.action, 'ACCEPT', 'After rule deletion, packet should fall through to default ACCEPT');
  assert.strictEqual(afterDeleteRes.matched_rule_handle, null);
  console.log(`  ✓ Dynamic rule #${tempRule.handle} deleted and traffic safely falls through to default policy`);

  // 7. Dynamic Blocklist Lifecycle Test (Add block -> Evaluate -> Unblock -> Verify)
  console.log('7. Testing dynamic blocklist lifecycle (Block, Execute, Unblock)...');
  const tempIp = '203.0.113.77';
  fw.addBlock(tempIp, 'Temporary block test');
  const blockedRes = fw.executePacket({ ip: tempIp, port: 80, protocol: 'TCP' });
  assert.strictEqual(blockedRes.action, 'DROP');
  assert.strictEqual(blockedRes.matched_set, '@blocklist');

  fw.removeBlock(tempIp);
  const unblockedRes = fw.executePacket({ ip: tempIp, port: 80, protocol: 'TCP' });
  assert.notStrictEqual(unblockedRes.matched_set, '@blocklist');
  console.log(`  ✓ Dynamic IP block and unblock lifecycle verified`);

  // 8. Batch Execution & Statistical Integrity
  console.log('8. Testing batch packet execution & statistics...');
  const batchPackets = [
    { ip: '198.51.100.42', port: 22, protocol: 'TCP', chain: 'input' },  // Rule match (SSH)
    { ip: '185.220.101.5', port: 443, protocol: 'TCP', chain: 'input' }, // Blocklist match
    { ip: '203.0.113.88', port: 23, protocol: 'TCP', chain: 'input' },   // Rule match (Telnet DROP)
    { ip: '172.16.0.4', port: 80, protocol: 'TCP', chain: 'forward' }    // Default Forward DROP
  ];
  const { results, stats } = fw.executeBatch(batchPackets);
  assert.strictEqual(stats.total, 4, 'Total packets count must match');
  assert.strictEqual(stats.accepted + stats.dropped + stats.rejected, 4, 'Sum of verdicts must match total');
  assert.strictEqual(stats.blocklistHits, 1, 'Blocklist hits must be 1');
  assert.strictEqual(stats.defaultHits, 1, 'Default fallthrough must be 1');
  console.log(`  ✓ Batch execution verified: ${stats.total} total (${stats.accepted} accepted, ${stats.dropped} dropped, ${stats.rejected} rejected)`);

  console.log('\n=============================================================');
  console.log('✅  ALL TESTS PASSED SUCCESSFULLY (100% RULE-DRIVEN VERIFICATION)');
  console.log('=============================================================\n');
}

runTests();
