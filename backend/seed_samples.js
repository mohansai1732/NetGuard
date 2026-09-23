/**
 * Seed realistic sample connection logs for local development testing.
 * This directly populates the SQLite database connection_logs table so
 * you can test the Dashboard graphs, counters, and table without waiting
 * for real Linux kernel traffic.
 */
const { db } = require('./db');

const sampleEvents = [
  {
    src_ip: '198.51.100.42',
    dst_ip: '192.168.1.10',
    port: '22',
    protocol: 'TCP',
    action: 'ACCEPT',
    matched_rule_handle: 10,
    matched_set: null,
    reason: 'SSH inbound from allowed management IP'
  },
  {
    src_ip: '203.0.113.88',
    dst_ip: '192.168.1.10',
    port: '23',
    protocol: 'TCP',
    action: 'DROP',
    matched_rule_handle: 40,
    matched_set: null,
    reason: 'Telnet probe dropped by security policy'
  },
  {
    src_ip: '185.220.101.5',
    dst_ip: '192.168.1.10',
    port: '443',
    protocol: 'TCP',
    action: 'DROP',
    matched_rule_handle: null,
    matched_set: '@blocklist',
    reason: 'Enforced via @blocklist set'
  },
  {
    src_ip: '10.0.0.15',
    dst_ip: '192.168.1.10',
    port: '443',
    protocol: 'TCP',
    action: 'ACCEPT',
    matched_rule_handle: 30,
    matched_set: null,
    reason: 'HTTPS web traffic'
  },
  {
    src_ip: '10.0.0.22',
    dst_ip: '192.168.1.10',
    port: '80',
    protocol: 'TCP',
    action: 'ACCEPT',
    matched_rule_handle: 20,
    matched_set: null,
    reason: 'HTTP web traffic'
  },
  {
    src_ip: '198.51.100.99',
    dst_ip: '192.168.1.10',
    port: '8080',
    protocol: 'TCP',
    action: 'REJECT',
    matched_rule_handle: null,
    matched_set: null,
    reason: 'Default reject unrouted port'
  },
  {
    src_ip: '45.143.200.12',
    dst_ip: '192.168.1.10',
    port: '22',
    protocol: 'TCP',
    action: 'DROP',
    matched_rule_handle: null,
    matched_set: '@blocklist',
    reason: 'Enforced via @blocklist set'
  },
  {
    src_ip: '192.168.1.105',
    dst_ip: '1.1.1.1',
    port: '53',
    protocol: 'UDP',
    action: 'ACCEPT',
    matched_rule_handle: 50,
    matched_set: null,
    reason: 'Outbound DNS lookup'
  },
  {
    src_ip: '192.168.1.150',
    dst_ip: '8.8.8.8',
    port: null,
    protocol: 'ICMP',
    action: 'ACCEPT',
    matched_rule_handle: 50,
    matched_set: null,
    reason: 'ICMP ping echo request'
  },
  {
    src_ip: '194.26.29.44',
    dst_ip: '192.168.1.10',
    port: '3389',
    protocol: 'TCP',
    action: 'DROP',
    matched_rule_handle: null,
    matched_set: '@blocklist',
    reason: 'Enforced via @blocklist set (CIDR match 194.26.29.0/24)'
  }
];

function seedSamples() {
  const insert = db.prepare(`
    INSERT INTO connection_logs (timestamp, src_ip, dst_ip, port, protocol, action, matched_rule_handle, matched_set, reason)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const now = Date.now();
  let count = 0;

  sampleEvents.forEach((evt, idx) => {
    // stagger timestamps across the last 30 minutes
    const eventTime = new Date(now - (sampleEvents.length - idx) * 180000).toISOString();
    insert.run(
      eventTime,
      evt.src_ip,
      evt.dst_ip,
      evt.port,
      evt.protocol,
      evt.action,
      evt.matched_rule_handle,
      evt.matched_set,
      evt.reason
    );
    count++;
  });

  console.log(`✓ Successfully seeded ${count} sample connection log events into netguard.db`);
}

seedSamples();
