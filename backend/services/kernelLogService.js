const { spawn } = require('child_process');
const systemStatus = require('./systemStatus');
const { recordConnectionLog } = require('../db');

// Distro-agnostic key-value kernel log parser
function parseKernelLogLine(line) {
  if (!line || typeof line !== 'string') return null;

  // Expect line prefixed with our rule logger: NETGUARD-(ACCEPT|DROP|REJECT):
  const prefixMatch = line.match(/NETGUARD-(ACCEPT|DROP|REJECT):\s*(.*)/);
  if (!prefixMatch) return null;

  const verdict = prefixMatch[1]; // ACCEPT, DROP, or REJECT
  const body = prefixMatch[2];

  // Robust Key-Value extraction: matches all KEY=VALUE tokens regardless of ordering
  const kv = {};
  const matches = body.matchAll(/([A-Z0-9]+)=([^\s]+)/g);
  for (const match of matches) {
    kv[match[1]] = match[2];
  }

  // Require at least a source IP to consider it a valid packet line
  if (!kv.SRC) return null;

  return {
    src_ip: kv.SRC,
    dst_ip: kv.DST || null,
    port: kv.DPT ? String(kv.DPT) : null,
    protocol: (kv.PROTO || 'TCP').toUpperCase(),
    action: verdict,
    matched_rule_handle: kv.HANDLE ? parseInt(kv.HANDLE, 10) : null,
    matched_set: kv.SET || null,
    reason: `kernel:${verdict.toLowerCase()}`
  };
}

let journalProcess = null;
let packetListeners = new Set();

function onPacket(callback) {
  packetListeners.add(callback);
  return () => packetListeners.delete(callback);
}

function broadcastPacket(packet) {
  packetListeners.forEach((cb) => {
    try {
      cb(packet);
    } catch (err) {
      console.error('[KERNEL LOG] Listener error:', err.message);
    }
  });
}

function startLogTailer() {
  if (!systemStatus.isLinux || !systemStatus.hasJournalctl) {
    console.log('\x1b[33m%s\x1b[0m', `[KERNEL LOG] Host platform is ${systemStatus.platform}. Real kernel log tailing is inactive.`);
    console.log('\x1b[33m%s\x1b[0m', '[KERNEL LOG] Zero simulated packets will be generated.');
    return;
  }

  try {
    console.log('[KERNEL LOG] Starting journalctl kernel log stream for NETGUARD prefixed rules...');
    // Spawns unprivileged journalctl with systemd-journal group permission
    journalProcess = spawn('journalctl', ['-kf', '-o', 'cat', '-g', 'NETGUARD'], {
      stdio: ['ignore', 'pipe', 'pipe']
    });

    journalProcess.stdout.on('data', (chunk) => {
      const lines = chunk.toString().split('\n');
      for (const line of lines) {
        const parsed = parseKernelLogLine(line.trim());
        if (parsed) {
          // Persist genuine event in SQLite
          const saved = recordConnectionLog(parsed);
          if (saved) {
            broadcastPacket(saved);
          }
        }
      }
    });

    journalProcess.stderr.on('data', (chunk) => {
      console.warn('[KERNEL LOG ERR]', chunk.toString().trim());
    });

    journalProcess.on('close', (code) => {
      console.log(`[KERNEL LOG] Log process exited with code ${code}`);
      journalProcess = null;
    });

    journalProcess.on('error', (err) => {
      console.error('[KERNEL LOG] Failed to spawn journalctl:', err.message);
      journalProcess = null;
    });
  } catch (err) {
    console.error('[KERNEL LOG] Error initializing kernel log stream:', err.message);
  }
}

function stopLogTailer() {
  if (journalProcess) {
    journalProcess.kill('SIGTERM');
    journalProcess = null;
  }
}

// Start logger on module load
startLogTailer();

module.exports = {
  parseKernelLogLine,
  onPacket,
  startLogTailer,
  stopLogTailer
};
