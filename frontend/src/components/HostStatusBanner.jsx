import React from 'react';
import { AlertCircle } from 'lucide-react';

export default function HostStatusBanner({ systemStatus }) {
  if (!systemStatus || systemStatus.available) return null;

  return (
    <div
      style={{
        background: '#1c1917',
        border: '1px solid #44403c',
        borderRadius: 'var(--radius-md)',
        padding: '12px 16px',
        display: 'flex',
        alignItems: 'flex-start',
        gap: '12px',
        marginBottom: '20px',
      }}
    >
      <AlertCircle size={18} color="#d97706" style={{ flexShrink: 0, marginTop: '2px' }} />
      <div style={{ fontSize: '0.82rem', color: '#d6d3d1', lineHeight: 1.5 }}>
        <strong style={{ color: '#f59e0b' }}>Firewall telemetry unavailable:</strong>{' '}
        {systemStatus.reason ||
          `NetGuard is currently running on a ${systemStatus.platform || 'non-Linux'} host. Real packet logging requires a Linux host with the nftables kernel subsystem and systemd-journal.`}{' '}
        <span style={{ color: '#a8a29e' }}>No simulated or mock packets are being generated.</span>
      </div>
    </div>
  );
}
