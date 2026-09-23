import React from 'react';

export default function TableEmptyState({ title, subtitle, colSpan = 6 }) {
  return (
    <tr>
      <td
        colSpan={colSpan}
        style={{
          textAlign: 'center',
          padding: '36px 20px',
          color: 'var(--text-dim)',
          fontSize: '0.82rem',
        }}
      >
        <div style={{ fontWeight: 500, color: 'var(--text-muted)', marginBottom: '4px' }}>
          {title || 'No records found'}
        </div>
        {subtitle && <div>{subtitle}</div>}
      </td>
    </tr>
  );
}
