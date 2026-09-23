const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const bcrypt = require('bcryptjs');
const config = require('../config');

// Ensure database directory exists
const dbDir = path.dirname(config.dbPath);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const db = new DatabaseSync(config.dbPath);

// Enable foreign keys and WAL mode for better concurrency and safety
db.exec('PRAGMA foreign_keys = ON;');

function initDatabase() {
  // Create tables
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'admin',
      must_change_password INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      admin_username TEXT NOT NULL,
      action TEXT NOT NULL,
      details TEXT,
      status TEXT DEFAULT 'SUCCESS',
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS blocked_ips (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip_or_cidr TEXT UNIQUE NOT NULL,
      reason TEXT,
      added_by TEXT DEFAULT 'admin',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS connection_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      src_ip TEXT NOT NULL,
      dst_ip TEXT NOT NULL,
      port TEXT,
      protocol TEXT NOT NULL,
      action TEXT NOT NULL,
      matched_rule_handle INTEGER,
      matched_set TEXT,
      reason TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_conn_timestamp ON connection_logs(timestamp);
    CREATE INDEX IF NOT EXISTS idx_conn_action ON connection_logs(action);
  `);

  // Seed default admin if no users exist
  const countStmt = db.prepare('SELECT COUNT(*) AS count FROM users');
  const userCount = countStmt.get().count;

  if (userCount === 0) {
    console.log('[DB] Seeding default admin account (admin / admin123)...');
    const defaultPasswordHash = bcrypt.hashSync('admin123', 10);
    const insertStmt = db.prepare(`
      INSERT INTO users (username, password_hash, role, must_change_password)
      VALUES (?, ?, 'admin', 1)
    `);
    insertStmt.run('admin', defaultPasswordHash);

    // Initial audit log entry
    const auditStmt = db.prepare(`
      INSERT INTO audit_logs (admin_username, action, details)
      VALUES ('system', 'SYSTEM_INIT', 'Seeded initial default admin account with password change requirement.')
    `);
    auditStmt.run();
  }
}

// Helper to log audit entries directly
function logAudit(adminUsername, action, details, status = 'SUCCESS') {
  try {
    const stmt = db.prepare(`
      INSERT INTO audit_logs (admin_username, action, details, status)
      VALUES (?, ?, ?, ?)
    `);
    stmt.run(
      adminUsername || 'anonymous',
      action,
      typeof details === 'object' ? JSON.stringify(details) : String(details),
      status
    );
  } catch (err) {
    console.error('[DB] Failed to write audit log:', err.message);
  }
}

// Real SQLite Connection Telemetry Methods
function recordConnectionLog(data) {
  try {
    const stmt = db.prepare(`
      INSERT INTO connection_logs (src_ip, dst_ip, port, protocol, action, matched_rule_handle, matched_set, reason)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const result = stmt.run(
      data.src_ip,
      data.dst_ip || '127.0.0.1',
      data.port ? String(data.port) : null,
      (data.protocol || 'TCP').toUpperCase(),
      data.action,
      data.matched_rule_handle || null,
      data.matched_set || null,
      data.reason || null
    );

    return {
      id: Number(result.lastInsertRowid),
      timestamp: new Date().toISOString(),
      src_ip: data.src_ip,
      dst_ip: data.dst_ip || '127.0.0.1',
      port: data.port,
      protocol: (data.protocol || 'TCP').toUpperCase(),
      action: data.action,
      matchedRuleHandle: data.matched_rule_handle,
      matchedSet: data.matched_set,
      reason: data.reason
    };
  } catch (err) {
    console.error('[DB] Failed to record connection log:', err.message);
    return null;
  }
}

function getRealStats() {
  try {
    const totalStmt = db.prepare('SELECT COUNT(*) as count FROM connection_logs');
    const acceptsStmt = db.prepare("SELECT COUNT(*) as count FROM connection_logs WHERE action = 'ACCEPT'");
    const dropsStmt = db.prepare("SELECT COUNT(*) as count FROM connection_logs WHERE action = 'DROP'");
    const rejectsStmt = db.prepare("SELECT COUNT(*) as count FROM connection_logs WHERE action = 'REJECT'");
    
    // Real packet rate based on packets logged in the last 60 seconds
    const recentMinuteStmt = db.prepare("SELECT COUNT(*) as count FROM connection_logs WHERE timestamp >= datetime('now', '-60 seconds')");

    const total = totalStmt.get().count;
    const accepts = acceptsStmt.get().count;
    const drops = dropsStmt.get().count;
    const rejects = rejectsStmt.get().count;
    const recentCount = recentMinuteStmt.get().count;
    const packetRate = Number((recentCount / 60).toFixed(1));

    return {
      period: 'realtime',
      totalPackets: total,
      accepts,
      drops,
      rejects,
      dropRatePercent: total > 0 ? Number(((drops / total) * 100).toFixed(2)) : 0,
      packetRate,
      timestamp: new Date().toISOString()
    };
  } catch (err) {
    console.error('[DB] Error calculating real stats:', err.message);
    return {
      period: 'realtime',
      totalPackets: 0,
      accepts: 0,
      drops: 0,
      rejects: 0,
      dropRatePercent: 0,
      packetRate: 0,
      timestamp: new Date().toISOString()
    };
  }
}

function getRecentConnectionLogs(limit = 30) {
  try {
    const stmt = db.prepare(`
      SELECT 
        id, 
        timestamp, 
        src_ip, 
        dst_ip, 
        port, 
        protocol, 
        action, 
        matched_rule_handle AS matchedRuleHandle, 
        matched_set AS matchedSet, 
        reason 
      FROM connection_logs 
      ORDER BY id DESC 
      LIMIT ?
    `);
    return stmt.all(limit);
  } catch (err) {
    console.error('[DB] Error fetching recent connection logs:', err.message);
    return [];
  }
}

function getRealTrafficHistory(limit = 15) {
  try {
    const stmt = db.prepare(`
      SELECT 
        strftime('%H:%M', timestamp) as time,
        SUM(CASE WHEN action = 'ACCEPT' THEN 1 ELSE 0 END) as accept,
        SUM(CASE WHEN action = 'DROP' THEN 1 ELSE 0 END) as drop,
        SUM(CASE WHEN action = 'REJECT' THEN 1 ELSE 0 END) as reject
      FROM connection_logs
      GROUP BY strftime('%Y-%m-%d %H:%M', timestamp)
      ORDER BY timestamp DESC
      LIMIT ?
    `);
    const rows = stmt.all(limit);
    return rows.reverse();
  } catch (err) {
    console.error('[DB] Error fetching traffic history:', err.message);
    return [];
  }
}

// Automatically initialize schema and seed default admin on module load
initDatabase();

module.exports = {
  db,
  initDatabase,
  logAudit,
  recordConnectionLog,
  getRealStats,
  getRecentConnectionLogs,
  getRealTrafficHistory
};
