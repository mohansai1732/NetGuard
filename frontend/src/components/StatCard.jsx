import React from 'react';

export default function StatCard({ title, value, type = 'neutral', subtitle }) {
  const typeMap = {
    accept: {
      color: 'var(--verdict-accept-text)',
      border: 'var(--verdict-accept-border)',
    },
    drop: {
      color: 'var(--verdict-drop-text)',
      border: 'var(--verdict-drop-border)',
    },
    reject: {
      color: 'var(--verdict-reject-text)',
      border: 'var(--verdict-reject-border)',
    },
    neutral: {
      color: 'var(--text-main)',
      border: 'var(--border-color)',
    },
  };

  const scheme = typeMap[type] || typeMap.neutral;

  return (
    <div
      className="card"
      style={{
        padding: '16px 18px',
        borderLeft: `3px solid ${scheme.color}`,
      }}
    >
      <div style={{ fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-dim)', fontWeight: 600 }}>
        {title}
      </div>
      <div
        className="mono"
        style={{
          fontSize: '1.75rem',
          fontWeight: 700,
          color: 'var(--text-main)',
          marginTop: '4px',
        }}
      >
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
      {subtitle && (
        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>
          {subtitle}
        </div>
      )}
    </div>
  );
}
