const fs = require('fs');
const path = require('path');

const RULES_FILE = path.resolve(__dirname, 'rules.json');
const BLOCKLIST_FILE = path.resolve(__dirname, 'blocklist.json');

// Default initial rules template (used only if rules.json does not exist)
function getDefaultRules() {
  return [
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
      comment: 'Allow SSH traffic',
      created_at: new Date().toISOString()
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
      comment: 'Allow HTTP web traffic',
      created_at: new Date().toISOString()
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
      comment: 'Allow HTTPS secure web traffic',
      created_at: new Date().toISOString()
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
      comment: 'Allow ICMP echo-request (ping)',
      created_at: new Date().toISOString()
    },
    {
      handle: 14,
      chain: 'input',
      table: 'filter',
      family: 'inet',
      protocol: 'udp',
      src_ip: null,
      dst_ip: null,
      port: '53',
      action: 'ACCEPT',
      comment: 'Allow DNS query traffic',
      created_at: new Date().toISOString()
    },
    {
      handle: 15,
      chain: 'input',
      table: 'filter',
      family: 'inet',
      protocol: 'tcp',
      src_ip: null,
      dst_ip: null,
      port: '23',
      action: 'DROP',
      comment: 'Drop unauthorized Telnet probes',
      created_at: new Date().toISOString()
    },
    {
      handle: 16,
      chain: 'input',
      table: 'filter',
      family: 'inet',
      protocol: 'tcp',
      src_ip: null,
      dst_ip: null,
      port: '3389',
      action: 'DROP',
      comment: 'Drop unauthorized external RDP scans',
      created_at: new Date().toISOString()
    },
    {
      handle: 17,
      chain: 'input',
      table: 'filter',
      family: 'inet',
      protocol: 'tcp',
      src_ip: null,
      dst_ip: null,
      port: '445',
      action: 'DROP',
      comment: 'Drop SMB exploitation probes',
      created_at: new Date().toISOString()
    },
    {
      handle: 18,
      chain: 'forward',
      table: 'filter',
      family: 'inet',
      protocol: 'any',
      src_ip: '10.0.0.0/8',
      dst_ip: null,
      port: null,
      action: 'ACCEPT',
      comment: 'Forward trusted internal LAN subnet',
      created_at: new Date().toISOString()
    }
  ];
}

// Default initial blocklist template (used only if blocklist.json does not exist)
function getDefaultBlocklist() {
  return [
    { ip_or_cidr: '185.220.101.5', reason: 'Tor exit node brute force' },
    { ip_or_cidr: '45.143.200.12', reason: 'Repeated SSH dictionary scan' },
    { ip_or_cidr: '194.26.29.0/24', reason: 'Known malicious botnet subnet' }
  ];
}

// Helper: Bitwise IPv4 CIDR subnet matching
function ipToInt(ip) {
  if (!ip || typeof ip !== 'string') return 0;
  const parts = ip.split('.');
  if (parts.length !== 4) return 0;
  return parts.reduce((acc, octet) => ((acc << 8) + parseInt(octet, 10)) >>> 0, 0);
}

function ipInCidr(ip, cidr) {
  if (!cidr || !ip) return false;
  const cleanCidr = String(cidr).trim();
  const cleanIp = String(ip).trim();
  if (cleanCidr === 'any' || cleanCidr === '0.0.0.0/0') return true;
  if (!cleanCidr.includes('/')) return cleanIp === cleanCidr;

  const [network, prefixStr] = cleanCidr.split('/');
  const prefix = parseInt(prefixStr, 10);
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return false;
  if (prefix === 0) return true;

  const mask = ((~0) << (32 - prefix)) >>> 0;
  return (ipToInt(cleanIp) & mask) === (ipToInt(network) & mask);
}

// Helper: Port matching (single port, comma-separated list, or port range)
function portMatches(packetPort, rulePort) {
  if (rulePort == null) return true;
  const rStr = String(rulePort).trim();
  if (rStr === '' || rStr.toLowerCase() === 'any') return true;
  if (packetPort == null) return false;

  const pStr = String(packetPort).trim();

  // Comma-separated ports, e.g. "80, 443"
  if (rStr.includes(',')) {
    const list = rStr.split(',').map(s => s.trim());
    return list.includes(pStr);
  }

  // Port range, e.g. "8000-8080"
  if (rStr.includes('-')) {
    const [startStr, endStr] = rStr.split('-');
    const start = parseInt(startStr, 10);
    const end = parseInt(endStr, 10);
    const pNum = parseInt(pStr, 10);
    if (!isNaN(start) && !isNaN(end) && !isNaN(pNum)) {
      return pNum >= start && pNum <= end;
    }
  }

  return pStr === rStr;
}

class Firewall {
  constructor(rulesPath = RULES_FILE, blocklistPath = BLOCKLIST_FILE) {
    this.rulesFile = rulesPath;
    this.blocklistFile = blocklistPath;
    this.chainPolicies = {
      input: 'ACCEPT',
      forward: 'DROP',
      output: 'ACCEPT'
    };
    this.rules = this.loadRules();
    this.blocklist = this.loadBlocklist();
  }

  // --- Rules Management ---
  loadRules() {
    try {
      if (fs.existsSync(this.rulesFile)) {
        const data = fs.readFileSync(this.rulesFile, 'utf8');
        const parsed = JSON.parse(data);
        if (Array.isArray(parsed)) {
          return parsed;
        }
      }
    } catch (err) {
      console.error(`Warning: could not read rules file (${this.rulesFile}):`, err.message);
    }
    const initial = getDefaultRules();
    this.saveRules(initial);
    return initial;
  }

  saveRules(rules = this.rules) {
    this.rules = rules;
    fs.writeFileSync(this.rulesFile, JSON.stringify(this.rules, null, 2), 'utf8');
  }

  getRules() {
    return [...this.rules];
  }

  addRule(ruleData) {
    const maxHandle = this.rules.reduce((max, r) => (r.handle > max ? r.handle : max), 0);
    const newRule = {
      handle: maxHandle + 1,
      chain: (ruleData.chain || 'input').toLowerCase(),
      table: ruleData.table || 'filter',
      family: ruleData.family || 'inet',
      protocol: ruleData.protocol ? ruleData.protocol.toLowerCase() : 'any',
      src_ip: ruleData.src_ip || null,
      dst_ip: ruleData.dst_ip || null,
      port: ruleData.port != null && String(ruleData.port).trim() !== '' ? String(ruleData.port).trim() : null,
      action: (ruleData.action || 'ACCEPT').toUpperCase(),
      comment: ruleData.comment || 'Custom firewall rule',
      created_at: new Date().toISOString()
    };
    this.rules.unshift(newRule);
    this.saveRules();
    return newRule;
  }

  deleteRule(handle) {
    const num = parseInt(handle, 10);
    const idx = this.rules.findIndex(r => r.handle === num);
    if (idx === -1) throw new Error(`Rule #${handle} not found`);
    const [deleted] = this.rules.splice(idx, 1);
    this.saveRules();
    return deleted;
  }

  resetRules() {
    this.rules = getDefaultRules();
    this.saveRules();
    return [...this.rules];
  }

  // --- Blocklist Management ---
  loadBlocklist() {
    try {
      if (fs.existsSync(this.blocklistFile)) {
        const data = fs.readFileSync(this.blocklistFile, 'utf8');
        const parsed = JSON.parse(data);
        if (Array.isArray(parsed)) {
          return parsed;
        }
      }
    } catch (err) {
      console.error(`Warning: could not read blocklist file (${this.blocklistFile}):`, err.message);
    }
    const initial = getDefaultBlocklist();
    this.saveBlocklist(initial);
    return initial;
  }

  saveBlocklist(list = this.blocklist) {
    this.blocklist = list;
    fs.writeFileSync(this.blocklistFile, JSON.stringify(this.blocklist, null, 2), 'utf8');
  }

  getBlocklist() {
    return [...this.blocklist];
  }

  addBlock(ip_or_cidr, reason = 'Blocked by firewall') {
    const trimmed = String(ip_or_cidr).trim();
    const existing = this.blocklist.find(b => b.ip_or_cidr === trimmed);
    if (existing) {
      existing.reason = reason;
    } else {
      this.blocklist.unshift({ ip_or_cidr: trimmed, reason });
    }
    this.saveBlocklist();
    return { ip_or_cidr: trimmed, reason };
  }

  removeBlock(ip_or_cidr) {
    const trimmed = String(ip_or_cidr).trim();
    const idx = this.blocklist.findIndex(b => b.ip_or_cidr === trimmed);
    if (idx === -1) return false;
    this.blocklist.splice(idx, 1);
    this.saveBlocklist();
    return true;
  }

  checkBlocklist(ip) {
    if (!ip) return null;
    for (const entry of this.blocklist) {
      if (ipInCidr(ip, entry.ip_or_cidr)) {
        return entry;
      }
    }
    return null;
  }

  // --- Chain Policies ---
  getChainPolicy(chain) {
    const c = (chain || 'input').toLowerCase();
    return this.chainPolicies[c] || (c === 'forward' ? 'DROP' : 'ACCEPT');
  }

  setChainPolicy(chain, policy) {
    const c = (chain || 'input').toLowerCase();
    this.chainPolicies[c] = (policy || 'ACCEPT').toUpperCase();
  }

  // --- Rule Execution Engine ---
  executePacket(packet = {}) {
    const src_ip = packet.src_ip || packet.ip || null;
    const dst_ip = packet.dst_ip || null;
    const protocol = packet.protocol ? String(packet.protocol).toUpperCase() : null;
    const port = packet.port != null && String(packet.port).trim() !== '' ? String(packet.port).trim() : null;
    const chain = (packet.chain || 'input').toLowerCase();

    // Step 1: Check dynamic Blocklist (@blocklist set)
    if (src_ip) {
      const blockedEntry = this.checkBlocklist(src_ip);
      if (blockedEntry) {
        return {
          action: 'DROP',
          verdict: 'DROP',
          src_ip,
          dst_ip,
          port,
          protocol,
          chain,
          matched_rule_handle: null,
          matched_set: '@blocklist',
          reason: `Blocked by @blocklist set (${blockedEntry.ip_or_cidr}: ${blockedEntry.reason})`
        };
      }
    }

    // Step 2: Evaluate dynamic rules loaded for this chain
    const chainRules = this.rules.filter(r => (r.chain || 'input').toLowerCase() === chain);

    for (const rule of chainRules) {
      // Protocol check: only matches if packet protocol satisfies rule requirement
      if (rule.protocol && rule.protocol.toLowerCase() !== 'any') {
        if (!protocol || rule.protocol.toUpperCase() !== protocol) {
          continue;
        }
      }

      // Source IP / CIDR check
      if (rule.src_ip && rule.src_ip !== 'any' && rule.src_ip !== '0.0.0.0/0') {
        if (!src_ip || !ipInCidr(src_ip, rule.src_ip)) {
          continue;
        }
      }

      // Destination IP / CIDR check
      if (rule.dst_ip && rule.dst_ip !== 'any' && rule.dst_ip !== '0.0.0.0/0') {
        if (!dst_ip || !ipInCidr(dst_ip, rule.dst_ip)) {
          continue;
        }
      }

      // Destination Port check
      if (rule.port != null && String(rule.port).toLowerCase() !== 'any') {
        if (port == null || !portMatches(port, rule.port)) {
          continue;
        }
      }

      // Dynamic rule match found! Verdict and explanation are driven solely by this rule
      const action = (rule.action || 'ACCEPT').toUpperCase();
      return {
        action,
        verdict: action,
        src_ip,
        dst_ip,
        port,
        protocol,
        chain,
        matched_rule_handle: rule.handle,
        matched_set: null,
        reason: `Matched Rule #${rule.handle}: ${rule.comment || `${action} rule`}`
      };
    }

    // Step 3: Default Chain Policy Fallthrough
    const defaultAction = this.getChainPolicy(chain);
    const defaultReason = `Default ${chain} chain policy: ${defaultAction}`;

    return {
      action: defaultAction,
      verdict: defaultAction,
      src_ip,
      dst_ip,
      port,
      protocol,
      chain,
      matched_rule_handle: null,
      matched_set: null,
      reason: defaultReason
    };
  }

  executeBatch(packets) {
    let accepted = 0;
    let dropped = 0;
    let rejected = 0;
    let blocklistHits = 0;
    let ruleHits = 0;
    let defaultHits = 0;

    const results = (packets || []).map(raw => {
      const pkt = typeof raw === 'string' ? { ip: raw } : raw;
      const res = this.executePacket(pkt);

      if (res.action === 'ACCEPT') accepted++;
      else if (res.action === 'DROP') dropped++;
      else if (res.action === 'REJECT') rejected++;

      if (res.matched_set) blocklistHits++;
      else if (res.matched_rule_handle != null) ruleHits++;
      else defaultHits++;

      return res;
    });

    return {
      results,
      stats: {
        total: results.length,
        accepted,
        dropped,
        rejected,
        blocklistHits,
        ruleHits,
        defaultHits
      }
    };
  }
}

module.exports = {
  Firewall,
  ipInCidr,
  portMatches,
  getDefaultRules,
  getDefaultBlocklist
};
