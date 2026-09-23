import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  Shield,
  Activity,
  Ban,
  FileText,
} from 'lucide-react';

export default function Sidebar() {
  const navItems = [
    { name: 'Activity', path: '/dashboard', icon: Activity },
    { name: 'Firewall Rules', path: '/rules', icon: Shield },
    { name: 'Blocked IPs', path: '/ip-management', icon: Ban },
    { name: 'Audit Trail', path: '/logs', icon: FileText },
  ];

  return (
    <aside
      style={{
        width: '220px',
        background: 'var(--bg-surface)',
        borderRight: '1px solid var(--border-color)',
        display: 'flex',
        flexDirection: 'column',
        height: '100vh',
        position: 'sticky',
        top: 0,
        zIndex: 60,
      }}
    >
      {/* Brand Header */}
      <div
        style={{
          padding: '16px 18px',
          borderBottom: '1px solid var(--border-color)',
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
        }}
      >
        <div
          style={{
            width: '28px',
            height: '28px',
            borderRadius: '4px',
            background: '#27272a',
            border: '1px solid #3f3f46',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#f4f4f5',
          }}
        >
          <Shield size={16} />
        </div>
        <div>
          <div style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-main)' }}>
            NetGuard
          </div>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>
            nftables firewall
          </div>
        </div>
      </div>

      {/* Navigation Links */}
      <nav style={{ padding: '12px 8px', display: 'flex', flexDirection: 'column', gap: '2px', flex: 1 }}>
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              style={({ isActive }) => ({
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                padding: '8px 12px',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.82rem',
                fontWeight: isActive ? 600 : 400,
                color: isActive ? '#f4f4f5' : '#a1a1aa',
                background: isActive ? '#27272a' : 'transparent',
                textDecoration: 'none',
                transition: 'background 0.15s ease',
              })}
            >
              <Icon size={16} />
              <span>{item.name}</span>
            </NavLink>
          );
        })}
      </nav>

      {/* Footer Info */}
      <div style={{ padding: '12px 16px', borderTop: '1px solid var(--border-color)', fontSize: '0.72rem', color: 'var(--text-dim)' }}>
        v1.0 • Stateless rule log
      </div>
    </aside>
  );
}
