#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const { Firewall } = require('./firewall');

const c = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
  gray: '\x1b[90m'
};

const fw = new Firewall();

function banner() {
  console.log(`${c.cyan}${c.bold}╔══════════════════════════════════════════════════════════════════════════╗${c.reset}`);
  console.log(`${c.cyan}${c.bold}║   🛡️   NETGUARD - Linux nftables Firewall Engine & Showcase Runner   ║${c.reset}`);
  console.log(`${c.cyan}${c.bold}╚══════════════════════════════════════════════════════════════════════════╝${c.reset}`);
  console.log(`${c.gray}   Rules File: ./rules.json | Incoming IPs: ./incoming_ips.json${c.reset}\n`);
}

function badge(action) {
  const act = (action || '').toUpperCase();
  if (act === 'ACCEPT') return `${c.green}${c.bold}[ACCEPT]${c.reset}`;
  if (act === 'DROP') return `${c.red}${c.bold}[ DROP ]${c.reset}`;
  if (act === 'REJECT') return `${c.yellow}${c.bold}[REJECT]${c.reset}`;
  return `[${act}]`;
}

function pad(str, width) {
  const s = String(str || '');
  if (s.length >= width) return s.slice(0, width);
  return s + ' '.repeat(width - s.length);
}

// ─────────────────────────────────────────────────────────────
// 1. RULES VIEW
// ─────────────────────────────────────────────────────────────

function listRules() {
  console.log(`\n${c.cyan}${c.bold}═══ ACTIVE FIREWALL RULES (rules.json) ═══${c.reset}\n`);
  const rules = fw.getRules();

  if (rules.length === 0) {
    console.log(`${c.yellow}No active firewall rules found.${c.reset}\n`);
    return;
  }

  console.log(`${c.bold}${pad('HANDLE', 8)} ${pad('CHAIN', 10)} ${pad('ACTION', 10)} ${pad('PROTO', 7)} ${pad('SRC IP', 18)} ${pad('PORT', 8)} COMMENT${c.reset}`);
  console.log(`${c.gray}────────────────────────────────────────────────────────────────────────────────────────${c.reset}`);

  for (const r of rules) {
    const actionBadge = r.action === 'ACCEPT' ? `${c.green}ACCEPT${c.reset}` :
                        r.action === 'DROP' ? `${c.red}DROP${c.reset}` :
                        `${c.yellow}${r.action}${c.reset}`;

    const handleStr = `${c.cyan}#${r.handle}${c.reset}`;
    const chainStr = r.chain || 'input';
    const protoStr = (r.protocol || 'any').toUpperCase();
    const srcStr = r.src_ip || 'any';
    const portStr = r.port || 'any';
    const commentStr = `${c.dim}${r.comment || ''}${c.reset}`;

    console.log(`${pad(handleStr, 17)} ${pad(chainStr, 10)} ${pad(actionBadge, 19)} ${pad(protoStr, 7)} ${pad(srcStr, 18)} ${pad(portStr, 8)} ${commentStr}`);
  }
  console.log(`${c.gray}────────────────────────────────────────────────────────────────────────────────────────${c.reset}`);
  console.log(`Total Rules: ${c.bold}${rules.length}${c.reset}\n`);
}

// ─────────────────────────────────────────────────────────────
// 2. BLOCKLIST VIEW
// ─────────────────────────────────────────────────────────────

function listBlocklist() {
  console.log(`\n${c.magenta}${c.bold}═══ ACTIVE IP BLOCKLIST (blocklist.json) ═══${c.reset}\n`);
  const list = fw.getBlocklist();

  if (list.length === 0) {
    console.log(`${c.yellow}No IPs currently in the blocklist.${c.reset}\n`);
    return;
  }

  console.log(`${c.bold}${pad('IP / CIDR SUBNET', 26)} REASON${c.reset}`);
  console.log(`${c.gray}───────────────────────────────────────────────────────────────────────${c.reset}`);

  for (const b of list) {
    console.log(`${pad(c.red + b.ip_or_cidr + c.reset, 35)} ${c.dim}${b.reason || ''}${c.reset}`);
  }
  console.log(`${c.gray}───────────────────────────────────────────────────────────────────────${c.reset}`);
  console.log(`Total Blocked: ${c.bold}${list.length}${c.reset}\n`);
}

// ─────────────────────────────────────────────────────────────
// 3. SHOWCASE RUNNER (Evaluate Incoming IPs against Rules)
// ─────────────────────────────────────────────────────────────

async function runShowcase(filePath, options = {}) {
  const targetFile = filePath || path.resolve(__dirname, 'incoming_ips.json');

  console.log(`\n${c.cyan}${c.bold}═══ EXECUTING FIREWALL RULES AGAINST INCOMING IPS ═══${c.reset}`);
  console.log(`${c.gray}Input file: ${targetFile}${c.reset}\n`);

  if (!fs.existsSync(targetFile)) {
    console.log(`${c.red}File not found: ${targetFile}${c.reset}\n`);
    return;
  }

  let packets = [];
  try {
    const raw = fs.readFileSync(targetFile, 'utf8');
    const parsed = JSON.parse(raw);
    packets = Array.isArray(parsed) ? parsed : (parsed.ips || []);
  } catch (err) {
    console.log(`${c.red}Failed to parse JSON in ${targetFile}: ${err.message}${c.reset}\n`);
    return;
  }

  if (packets.length === 0) {
    console.log(`${c.yellow}No incoming IP entries found in file.${c.reset}\n`);
    return;
  }

  console.log(`${c.bold}Evaluating ${packets.length} incoming packets directly against active ruleset...${c.reset}\n`);

  const { results, stats } = fw.executeBatch(packets);

  for (let i = 0; i < results.length; i++) {
    const res = results[i];
    const ipPort = `${res.src_ip || '*'}${res.port ? ':' + res.port : ''}`;
    const proto = pad(res.protocol || 'ANY', 5);
    const chainStr = `[chain: ${res.chain || 'input'}]`;
    const actionBadge = badge(res.action);
    const reasonText = `${c.dim}${res.reason}${c.reset}`;

    console.log(`[${pad(i + 1, 2)}/${results.length}] ${actionBadge} ${c.bold}${pad(ipPort, 22)}${c.reset} ${proto} ${pad(chainStr, 17)} -> ${reasonText}`);

    if (!options.fast && process.stdout.isTTY) {
      await new Promise(r => setTimeout(r, 40));
    }
  }

  const acceptPct = stats.total > 0 ? ((stats.accepted / stats.total) * 100).toFixed(1) : 0;
  const dropPct = stats.total > 0 ? ((stats.dropped / stats.total) * 100).toFixed(1) : 0;
  const rejectPct = stats.total > 0 ? ((stats.rejected / stats.total) * 100).toFixed(1) : 0;

  console.log(`\n${c.cyan}${c.bold}══════════════════ SHOWCASE EXECUTION SUMMARY ══════════════════${c.reset}`);
  console.log(`  Total Evaluated:      ${c.bold}${stats.total}${c.reset} packets`);
  console.log(`  ${c.green}● Accepted:${c.reset}           ${c.bold}${stats.accepted}${c.reset} (${acceptPct}%)`);
  console.log(`  ${c.red}● Dropped:${c.reset}            ${c.bold}${stats.dropped}${c.reset} (${dropPct}%)`);
  console.log(`  ${c.yellow}● Rejected:${c.reset}           ${c.bold}${stats.rejected}${c.reset} (${rejectPct}%)`);
  console.log(`  Blocklist Matches:    ${c.magenta}${stats.blocklistHits}${c.reset}`);
  console.log(`  Ruleset Matches:      ${c.cyan}${stats.ruleHits}${c.reset}`);
  console.log(`  Default Fallthroughs: ${c.gray}${stats.defaultHits}${c.reset}`);
  console.log(`${c.cyan}${c.bold}════════════════════════════════════════════════════════════════${c.reset}\n`);
}

// ─────────────────────────────────────────────────────────────
// 4. TEST SINGLE IP PACKET
// ─────────────────────────────────────────────────────────────

function testSingle(ip, port = null, proto = null, chain = 'input') {
  const packet = {
    ip: ip || null,
    chain: chain || 'input'
  };
  if (port != null && String(port).trim() !== '') packet.port = String(port).trim();
  if (proto && String(proto).trim().toLowerCase() !== 'any') packet.protocol = String(proto).trim().toUpperCase();

  const res = fw.executePacket(packet);
  const targetPort = res.port ? `:${res.port}` : '';
  const protoStr = res.protocol ? ` [${res.protocol}]` : ' [ANY]';
  console.log(`${badge(res.action)} ${c.bold}${res.src_ip || '*'}${targetPort}${c.reset}${protoStr} [chain: ${res.chain}] -> ${res.reason}`);
}

// ─────────────────────────────────────────────────────────────
// 5. INTERACTIVE MENU
// ─────────────────────────────────────────────────────────────

function ask(rl, q) {
  return new Promise(res => rl.question(q, answer => res(answer.trim())));
}

async function interactiveMenu() {
  banner();
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  let running = true;

  while (running) {
    console.log(`${c.bold}ACTIONS:${c.reset}`);
    console.log(`  ${c.green}[1]${c.reset} 🚀 ${c.bold}Run Showcase (Execute incoming_ips.json)${c.reset}`);
    console.log(`  ${c.yellow}[2]${c.reset} 🎯 Test Single IP Address`);
    console.log(`  ${c.cyan}[3]${c.reset} 📋 View Rules (rules.json)`);
    console.log(`  ${c.cyan}[4]${c.reset} ➕ Add Rule`);
    console.log(`  ${c.cyan}[5]${c.reset} ❌ Delete Rule`);
    console.log(`  ${c.magenta}[6]${c.reset} 🛡️  View Blocklist (blocklist.json)`);
    console.log(`  ${c.magenta}[7]${c.reset} 🚫 Block IP / CIDR`);
    console.log(`  ${c.magenta}[8]${c.reset} 🔓 Unblock IP / CIDR`);
    console.log(`  ${c.yellow}[9]${c.reset} 🔄 Reset Rules to Defaults`);
    console.log(`  ${c.gray}[0]${c.reset} 🚪 Exit\n`);

    const opt = await ask(rl, `${c.bold}Select option (0-9): ${c.reset}`);

    switch (opt) {
      case '1':
        await runShowcase(null, { fast: false });
        break;
      case '2': {
        const ip = await ask(rl, 'Source IP address: ');
        if (!ip) break;
        const port = await ask(rl, 'Port (leave blank for any): ');
        const proto = await ask(rl, 'Protocol (tcp / udp / icmp / any) [leave blank for any]: ');
        const chain = (await ask(rl, 'Chain (input / forward / output) [default: input]: ')) || 'input';
        console.log('');
        testSingle(ip, port || null, proto || null, chain);
        break;
      }
      case '3':
        listRules();
        break;
      case '4': {
        const chain = (await ask(rl, 'Chain (input / forward / output) [default: input]: ')) || 'input';
        const action = (await ask(rl, 'Action (ACCEPT / DROP / REJECT) [default: DROP]: ')) || 'DROP';
        const proto = (await ask(rl, 'Protocol (tcp / udp / icmp / any) [default: any]: ')) || 'any';
        const src_ip = (await ask(rl, 'Source IP or CIDR (blank for any): ')) || null;
        const dst_ip = (await ask(rl, 'Destination IP or CIDR (blank for any): ')) || null;
        const port = (await ask(rl, 'Port, list, or range (blank for any): ')) || null;
        const comment = (await ask(rl, 'Rule description / comment: ')) || 'Custom rule';
        const rule = fw.addRule({ chain, action, protocol: proto, src_ip, dst_ip, port, comment });
        console.log(`\n${c.green}✓ Added rule #${rule.handle}!${c.reset}\n`);
        break;
      }
      case '5': {
        const handle = await ask(rl, 'Rule handle number to delete: ');
        try {
          fw.deleteRule(handle);
          console.log(`\n${c.green}✓ Deleted rule #${handle}!${c.reset}\n`);
        } catch (e) {
          console.log(`\n${c.red}Error: ${e.message}${c.reset}\n`);
        }
        break;
      }
      case '6':
        listBlocklist();
        break;
      case '7': {
        const ip = await ask(rl, 'IP or CIDR to block (e.g. 194.26.29.0/24): ');
        if (!ip) break;
        const reason = (await ask(rl, 'Reason: ')) || 'Blocked via terminal';
        fw.addBlock(ip, reason);
        console.log(`\n${c.green}✓ Blocked '${ip}'!${c.reset}\n`);
        break;
      }
      case '8': {
        const ip = await ask(rl, 'IP or CIDR to unblock: ');
        if (!ip) break;
        const removed = fw.removeBlock(ip);
        if (removed) console.log(`\n${c.green}✓ Unblocked '${ip}'!${c.reset}\n`);
        else console.log(`\n${c.yellow}'${ip}' not found in blocklist.${c.reset}\n`);
        break;
      }
      case '9': {
        fw.resetRules();
        console.log(`\n${c.green}✓ Rules reset to default configuration!${c.reset}\n`);
        break;
      }
      case '0':
      case 'exit':
      case 'q':
        console.log(`\n${c.cyan}Goodbye! 🛡️${c.reset}\n`);
        running = false;
        rl.close();
        process.exit(0);
        break;
      default:
        console.log(`\n${c.yellow}Invalid option.${c.reset}\n`);
    }

    if (running) {
      await ask(rl, `${c.dim}Press Enter to continue...${c.reset}`);
      console.log('');
    }
  }
}

// ─────────────────────────────────────────────────────────────
// 6. CLI DISPATCHER
// ─────────────────────────────────────────────────────────────

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    await interactiveMenu();
    return;
  }

  const cmd = args[0].toLowerCase();

  switch (cmd) {
    case 'showcase': {
      banner();
      const fileArg = args.slice(1).find(a => !a.startsWith('-')) || null;
      await runShowcase(fileArg, { fast: args.includes('--fast') });
      break;
    }

    case 'test':
    case 'test-ip': {
      const ip = args[1];
      if (!ip) {
        console.error('Usage: node cli.js test <ip> [port] [protocol] [chain]');
        process.exit(1);
      }
      const port = args[2] || null;
      const proto = args[3] || null;
      const chain = args[4] || 'input';
      testSingle(ip, port, proto, chain);
      break;
    }

    case 'rules': {
      const sub = (args[1] || 'list').toLowerCase();
      if (sub === 'list') {
        listRules();
      } else if (sub === 'delete' || sub === 'rm') {
        const handle = args[2];
        if (!handle) {
          console.error('Usage: node cli.js rules delete <handle>');
          process.exit(1);
        }
        fw.deleteRule(handle);
        console.log(`✓ Deleted rule #${handle}`);
      } else if (sub === 'reset') {
        fw.resetRules();
        console.log('✓ Reset rules to defaults.');
      } else {
        console.log('Usage: node cli.js rules [list | delete <handle> | reset]');
      }
      break;
    }

    case 'block': {
      const ip = args[1];
      const reason = args.slice(2).join(' ') || 'Blocked via CLI';
      if (!ip) {
        console.error('Usage: node cli.js block <ip_or_cidr> [reason]');
        process.exit(1);
      }
      fw.addBlock(ip, reason);
      console.log(`✓ Blocked ${ip} (${reason})`);
      break;
    }

    case 'unblock': {
      const ip = args[1];
      if (!ip) {
        console.error('Usage: node cli.js unblock <ip_or_cidr>');
        process.exit(1);
      }
      const ok = fw.removeBlock(ip);
      if (ok) console.log(`✓ Unblocked ${ip}`);
      else console.log(`'${ip}' was not in blocklist`);
      break;
    }

    case 'blocklist': {
      listBlocklist();
      break;
    }

    case '--help':
    case '-h':
    case 'help': {
      banner();
      console.log(`${c.bold}USAGE:${c.reset}`);
      console.log('  node cli.js                          Start interactive terminal menu');
      console.log('  node cli.js showcase [file]          Run incoming IP addresses showcase');
      console.log('  node cli.js test <ip> [port] [proto] Test single IP packet verdict');
      console.log('  node cli.js rules                    List active firewall rules');
      console.log('  node cli.js rules delete <handle>    Delete rule by handle ID');
      console.log('  node cli.js rules reset              Reset rules to default');
      console.log('  node cli.js block <ip> [reason]      Block IP or CIDR subnet');
      console.log('  node cli.js unblock <ip>             Unblock IP or CIDR subnet');
      console.log('  node cli.js blocklist                List active blocklist\n');
      break;
    }

    default:
      console.error(`Unknown command: ${cmd}. Run "node cli.js --help" for usage.`);
      process.exit(1);
  }
}

if (require.main === module) {
  main().catch(err => {
    console.error('Fatal Error:', err);
    process.exit(1);
  });
}

module.exports = {
  fw,
  runShowcase,
  listRules,
  listBlocklist
};
