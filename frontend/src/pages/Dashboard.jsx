import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { wsClient } from '../services/websocket';
import StatCard from '../components/StatCard';
import StatusBadge from '../components/StatusBadge';
import TableEmptyState from '../components/TableEmptyState';
import HostStatusBanner from '../components/HostStatusBanner';
import { RefreshCw } from 'lucide-react';

export default function Dashboard() {
  const [stats, setStats] = useState({
    available: true,
    systemStatus: null,
    totalPackets: 0,
    accepts: 0,
    drops: 0,
    rejects: 0,
  });
  const [recentLogs, setRecentLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    setLoading(true);
    try {
      const [statsData, logsData] = await Promise.all([
        api.stats.getSummary(),
        api.logs.getRecent(50),
      ]);
      setStats(statsData);
      setRecentLogs(logsData.logs || []);
    } catch (err) {
      console.error('Failed to load dashboard data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();

    // Subscribe to authenticated WebSocket stream for real kernel events
    const unsubscribe = wsClient.subscribe((data) => {
      if (data.type === 'system_status' && data.status) {
        setStats((prev) => ({
          ...prev,
          available: data.status.available,
          systemStatus: data.status,
        }));
      }

      if (data.type === 'traffic_packet' && data.packet) {
        const packet = data.packet;

        // Prepend genuine kernel event
        setRecentLogs((prev) => [packet, ...prev.slice(0, 49)]);

        // Dynamically increment real verdict counters
        setStats((prev) => {
          const total = (prev.totalPackets || 0) + 1;
          const accepts = packet.action === 'ACCEPT' ? (prev.accepts || 0) + 1 : prev.accepts;
          const drops = packet.action === 'DROP' ? (prev.drops || 0) + 1 : prev.drops;
          const rejects = packet.action === 'REJECT' ? (prev.rejects || 0) + 1 : prev.rejects;
          return {
            ...prev,
            totalPackets: total,
            accepts,
            drops,
            rejects,
          };
        });
      }
    });

    return () => unsubscribe();
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Page Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h1 style={{ fontSize: '1.3rem', fontWeight: 600, color: 'var(--text-main)', margin: 0 }}>
            Firewall Activity
          </h1>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', margin: '2px 0 0' }}>
            Real-time kernel log stream and stored event verdicts.
          </p>
        </div>

        <button
          onClick={loadData}
          className="btn btn-secondary btn-sm"
          disabled={loading}
        >
          <RefreshCw size={13} className={loading ? 'spin' : ''} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Host Status Notice (Displayed if not running on Linux with nftables) */}
      <HostStatusBanner systemStatus={stats.systemStatus} />

      {/* Three Real Verdict Metric Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px' }}>
        <StatCard
          title="Accepted"
          value={stats.accepts}
          type="accept"
          subtitle="Packets allowed by rules"
        />
        <StatCard
          title="Dropped"
          value={stats.drops}
          type="drop"
          subtitle="Packets discarded by rules & sets"
        />
        <StatCard
          title="Rejected"
          value={stats.rejects}
          type="reject"
          subtitle="Packets refused with ICMP reply"
        />
      </div>

      {/* Live Event Feed Table */}
      <div className="card" style={{ overflow: 'hidden' }}>
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border-color)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <h2 style={{ fontSize: '0.88rem', fontWeight: 600, color: 'var(--text-main)', margin: 0 }}>
            Event Log Feed
          </h2>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
            Showing {recentLogs.length} events
          </span>
        </div>

        <div className="data-table-container" style={{ border: 'none', borderRadius: 0 }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Protocol</th>
                <th>Verdict</th>
                <th>Rule / Set</th>
              </tr>
            </thead>
            <tbody>
              {recentLogs.length === 0 ? (
                <TableEmptyState
                  title="No kernel firewall events recorded yet"
                  subtitle={
                    stats.systemStatus?.available
                      ? 'Listening to journalctl for NETGUARD prefixed rules. Traffic hitting firewall logging rules will appear here.'
                      : 'Host is not Linux. Connect to a Linux host with nftables and systemd-journal to stream real kernel events.'
                  }
                  colSpan={6}
                />
              ) : (
                recentLogs.map((log, index) => (
                  <tr key={log.id || `${log.timestamp}-${index}`}>
                    <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-dim)', whiteSpace: 'nowrap' }}>
                      {new Date(log.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="mono" style={{ fontWeight: 500, color: '#f4f4f5' }}>
                      {log.src_ip}{log.src_port ? `:${log.src_port}` : ''}
                    </td>
                    <td className="mono" style={{ color: 'var(--text-muted)' }}>
                      {log.dst_ip || '—'}{log.port ? `:${log.port}` : ''}
                    </td>
                    <td>
                      <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                        {log.protocol || 'TCP'}
                      </span>
                    </td>
                    <td>
                      <StatusBadge verdict={log.action} />
                    </td>
                    <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                      {log.matchedRuleHandle ? (
                        <span>Rule #{log.matchedRuleHandle}</span>
                      ) : log.matchedSet ? (
                        <span>@{log.matchedSet}</span>
                      ) : (
                        <span>{log.reason || '—'}</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
