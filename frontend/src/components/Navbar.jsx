import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { wsClient } from '../services/websocket';
import { api } from '../services/api';
import AccountModal from './AccountModal';
import { LogOut, User, Server } from 'lucide-react';

export default function Navbar() {
  const { user, logout } = useAuth();
  const [wsOnline, setWsOnline] = useState(wsClient.isConnected);
  const [systemStatus, setSystemStatus] = useState(null);
  const [isAccountModalOpen, setIsAccountModalOpen] = useState(false);

  useEffect(() => {
    const unsubscribe = wsClient.onStatusChange((status) => {
      setWsOnline(status);
    });

    api.stats.getSystemStatus()
      .then((status) => setSystemStatus(status))
      .catch(() => {});

    return unsubscribe;
  }, []);

  return (
    <>
      <header
        style={{
          height: '52px',
          borderBottom: '1px solid var(--border-color)',
          background: 'var(--bg-surface)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0 20px',
          position: 'sticky',
          top: 0,
          zIndex: 50,
        }}
      >
        {/* Left: System context */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '0.75rem',
              color: 'var(--text-muted)',
              padding: '3px 8px',
              background: '#18181b',
              border: '1px solid var(--border-color)',
              borderRadius: 'var(--radius-sm)',
            }}
          >
            <Server size={13} />
            <span>
              Host: <strong className="mono">{systemStatus?.platform || 'local'}</strong>{' '}
              {systemStatus?.available ? (
                <span style={{ color: '#22c55e' }}>(nftables active)</span>
              ) : (
                <span style={{ color: '#a1a1aa' }}>(no nftables)</span>
              )}
            </span>
          </div>
        </div>

        {/* Right: Static WS status + Account Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          {/* Static WebSocket status pill (no pulsing or glowing animations) */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '0.75rem',
              color: wsOnline ? '#22c55e' : '#a1a1aa',
              padding: '3px 8px',
              background: '#18181b',
              border: '1px solid var(--border-color)',
              borderRadius: 'var(--radius-sm)',
            }}
          >
            <span className={wsOnline ? 'status-dot' : 'status-dot-off'} />
            <span>{wsOnline ? 'Stream connected' : 'Disconnected'}</span>
          </div>

          {/* Account & Settings button */}
          <button
            onClick={() => setIsAccountModalOpen(true)}
            className="btn btn-secondary btn-sm"
            style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            <User size={13} />
            <span>{user?.username || 'admin'}</span>
          </button>

          {/* Logout button */}
          <button
            onClick={logout}
            className="btn btn-secondary btn-sm"
            title="Sign out"
          >
            <LogOut size={13} />
          </button>
        </div>
      </header>

      <AccountModal
        isOpen={isAccountModalOpen}
        onClose={() => setIsAccountModalOpen(false)}
        systemStatus={systemStatus}
      />
    </>
  );
}
