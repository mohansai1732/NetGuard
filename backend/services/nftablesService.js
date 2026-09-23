const { db, logAudit } = require('../db');

// Realistic initial nftables ruleset structure matching `nft -j list ruleset`
let nextHandle = 100;

let mockRules = [
  {
    handle: 10,
    chain: 'input',
    table: 'filter',
    family: 'inet',
    protocol: 'tcp',
    src_ip: null,
    dst_ip: null,
    port: '22',
    action: 'ACCEPT',
    comment: 'Allow SSH administration',
    created_at: new Date(Date.now() - 3600000 * 24).toISOString()
  },
  {
    handle: 11,
    chain: 'input',
    table: 'filter',
    family: 'inet',
    protocol: 'tcp',
    src_ip: null,
    dst_ip: null,
    port: '80',
    action: 'ACCEPT',
    comment: 'Allow HTTP traffic',
    created_at: new Date(Date.now() - 3600000 * 20).toISOString()
  },
  {
    handle: 12,
    chain: 'input',
    table: 'filter',
    family: 'inet',
    protocol: 'tcp',
    src_ip: null,
    dst_ip: null,
    port: '443',
    action: 'ACCEPT',
    comment: 'Allow HTTPS traffic',
    created_at: new Date(Date.now() - 3600000 * 18).toISOString()
  },
  {
    handle: 13,
    chain: 'input',
    table: 'filter',
    family: 'inet',
    protocol: 'icmp',
    src_ip: null,
    dst_ip: null,
    port: null,
    action: 'ACCEPT',
    comment: 'Allow ICMP echo-request',
    created_at: new Date(Date.now() - 3600000 * 12).toISOString()
  },
  {
    handle: 14,
    chain: 'input',
    table: 'filter',
    family: 'inet',
    protocol: 'tcp',
    src_ip: '198.51.100.0/24',
    dst_ip: null,
    port: '23',
    action: 'DROP',
    comment: 'Drop unauthorized Telnet probes',
    created_at: new Date(Date.now() - 3600000 * 6).toISOString()
  },
  {
    handle: 15,
    chain: 'forward',
    table: 'filter',
    family: 'inet',
    protocol: 'any',
    src_ip: '10.0.0.0/8',
    dst_ip: null,
    port: null,
    action: 'ACCEPT',
    comment: 'Forward trusted internal LAN subnet',
    created_at: new Date(Date.now() - 3600000 * 2).toISOString()
  }
];

// In-memory blocklist set synced with DB
let inMemoryBlocklist = new Set();

function syncBlocklistFromDb() {
  try {
    const rows = db.prepare('SELECT ip_or_cidr FROM blocked_ips').all();
    inMemoryBlocklist.clear();
    rows.forEach(r => inMemoryBlocklist.add(r.ip_or_cidr));
  } catch (err) {
    console.error('[NFTABLES] Error syncing blocklist from DB:', err.message);
  }
}

// Seed initial blocked IPs if empty
function seedInitialBlocklist() {
  try {
    const count = db.prepare('SELECT COUNT(*) AS count FROM blocked_ips').get().count;
    if (count === 0) {
      const initialIps = [
        { ip: '185.220.101.5', reason: 'Tor exit node brute force' },
        { ip: '45.143.200.12', reason: 'Repeated SSH dictionary scan' },
        { ip: '194.26.29.0/24', reason: 'Known malicious botnet subnet' }
      ];
      const insert = db.prepare('INSERT INTO blocked_ips (ip_or_cidr, reason, added_by) VALUES (?, ?, ?)');
      initialIps.forEach(item => {
        insert.run(item.ip, item.reason, 'system');
      });
      syncBlocklistFromDb();
    } else {
      syncBlocklistFromDb();
    }
  } catch (err) {
    console.error('[NFTABLES] Error seeding initial blocklist:', err.message);
  }
}

// Initial sync
seedInitialBlocklist();

// Helper: check if single IP matches rule IP or CIDR
function ipMatches(packetIp, ruleIpOrCidr) {
  if (!ruleIpOrCidr || ruleIpOrCidr === 'any') return true;
  if (!packetIp) return false;
  if (ruleIpOrCidr === packetIp) return true;

  // Simple CIDR prefix matching for /24 or /16 IPv4
  if (ruleIpOrCidr.includes('/')) {
    const [network, prefixStr] = ruleIpOrCidr.split('/');
    const prefix = parseInt(prefixStr, 10);
    if (prefix === 24) {
      const netParts = network.split('.').slice(0, 3).join('.');
      return packetIp.startsWith(netParts + '.');
    }
    if (prefix === 16) {
      const netParts = network.split('.').slice(0, 2).join('.');
      return packetIp.startsWith(netParts + '.');
    }
    if (prefix === 8) {
      const netPart = network.split('.')[0];
      return packetIp.startsWith(netPart + '.');
    }
  }
  return false;
}

const nftablesService = {
  // Returns raw nftables JSON format structure alongside parsed convenience rules
  async listRuleset() {
    return {
      version: '1.0.8',
      nftables: [
        { metainfo: { version: '1.0.8', release_name: 'Fearless Coyote', json_schema_version: 1 } },
        { table: { family: 'inet', name: 'filter', handle: 1 } },
        { chain: { family: 'inet', table: 'filter', name: 'input', type: 'filter', hook: 'input', prio: 0, policy: 'accept' } },
        { chain: { family: 'inet', table: 'filter', name: 'forward', type: 'filter', hook: 'forward', prio: 0, policy: 'drop' } },
        { chain: { family: 'inet', table: 'filter', name: 'output', type: 'filter', hook: 'output', prio: 0, policy: 'accept' } },
        { set: { family: 'inet', table: 'filter', name: 'blocklist', type: 'ipv4_addr', flags: ['interval'] } },
        ...mockRules.map(r => ({
          rule: {
            family: r.family,
            table: r.table,
            chain: r.chain,
            handle: r.handle,
            expr: [
              ...(r.protocol && r.protocol !== 'any' ? [{ match: { op: '==', left: { payload: { protocol: r.protocol } } } }] : []),
              ...(r.src_ip ? [{ match: { op: '==', left: { payload: { field: 'saddr' } }, right: r.src_ip } }] : []),
              ...(r.port ? [{ match: { op: '==', left: { payload: { field: 'dport' } }, right: r.port } }] : []),
              { [r.action.toLowerCase()]: null }
            ],
            comment: r.comment
          }
        }))
      ],
      rules: [...mockRules]
    };
  },

  async addRule(ruleData, adminUser = 'admin') {
    const handle = ++nextHandle;
    const newRule = {
      handle,
      chain: ruleData.chain,
      table: 'filter',
      family: 'inet',
      protocol: ruleData.protocol || 'any',
      src_ip: ruleData.src_ip || null,
      dst_ip: ruleData.dst_ip || null,
      port: ruleData.port || null,
      action: ruleData.action,
      comment: ruleData.comment || `Created via NetGuard by ${adminUser}`,
      created_at: new Date().toISOString()
    };

    mockRules.unshift(newRule);

    logAudit(
      adminUser,
      'RULE_ADD',
      {
        handle,
        chain: newRule.chain,
        action: newRule.action,
        protocol: newRule.protocol,
        src_ip: newRule.src_ip,
        port: newRule.port
      }
    );

    return newRule;
  },

  async updateRule(handle, updateData, adminUser = 'admin') {
    const numHandle = parseInt(handle, 10);
    const index = mockRules.findIndex(r => r.handle === numHandle);
    if (index === -1) {
      throw new Error(`Rule with handle #${handle} not found`);
    }

    const previousRule = { ...mockRules[index] };
    mockRules[index] = {
      ...mockRules[index],
      ...updateData,
      handle: numHandle // immutable handle
    };

    logAudit(
      adminUser,
      'RULE_UPDATE',
      {
        handle: numHandle,
        before: previousRule,
        after: mockRules[index]
      }
    );

    return mockRules[index];
  },

  async deleteRule(handle, adminUser = 'admin') {
    const numHandle = parseInt(handle, 10);
    const index = mockRules.findIndex(r => r.handle === numHandle);
    if (index === -1) {
      throw new Error(`Rule with handle #${handle} not found`);
    }

    const deleted = mockRules.splice(index, 1)[0];

    logAudit(
      adminUser,
      'RULE_DELETE',
      {
        handle: numHandle,
        deletedRule: deleted
      }
    );

    return { success: true, deletedHandle: numHandle };
  },

  // IP Blocklist Set Operations
  async getBlocklist() {
    return db.prepare('SELECT id, ip_or_cidr, reason, added_by, created_at FROM blocked_ips ORDER BY id DESC').all();
  },

  async addToBlocklist(ip, reason = 'Blocked via dashboard', adminUser = 'admin') {
    const stmt = db.prepare(`
      INSERT INTO blocked_ips (ip_or_cidr, reason, added_by)
      VALUES (?, ?, ?)
    `);
    stmt.run(ip, reason, adminUser);
    inMemoryBlocklist.add(ip);

    logAudit(adminUser, 'IP_BLOCK', { ip, reason });
    return { ip, reason, added_by: adminUser, created_at: new Date().toISOString() };
  },

  async removeFromBlocklist(ip, adminUser = 'admin') {
    const stmt = db.prepare('DELETE FROM blocked_ips WHERE ip_or_cidr = ?');
    const result = stmt.run(ip);
    inMemoryBlocklist.delete(ip);

    logAudit(adminUser, 'IP_UNBLOCK', { ip });
    return { success: true, removedIp: ip, changes: result.changes };
  }
};

module.exports = nftablesService;
