const os = require('os');
const { execSync } = require('child_process');

function checkBinary(name) {
  try {
    const cmd = process.platform === 'win32' ? `where ${name}` : `which ${name}`;
    execSync(cmd, { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

const isLinux = process.platform === 'linux';
const hasNft = isLinux && checkBinary('nft');
const hasJournalctl = isLinux && checkBinary('journalctl');

const systemStatus = {
  isLinux,
  hasNft,
  hasJournalctl,
  platform: process.platform,
  arch: process.arch,
  nodeVersion: process.version,
  isAvailable() {
    return isLinux && hasNft;
  },
  getStatus() {
    const available = this.isAvailable();
    return {
      available,
      platform: process.platform,
      arch: process.arch,
      nodeVersion: process.version,
      subsystems: {
        linux: isLinux,
        nftablesBinary: hasNft,
        journalctl: hasJournalctl,
      },
      reason: available
        ? 'Linux kernel with nftables detected.'
        : `Firewall telemetry unavailable — running on ${process.platform} without Linux nftables kernel subsystem.`
    };
  }
};

module.exports = systemStatus;
