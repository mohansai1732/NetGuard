import React from 'react';

export default function StatusBadge({ verdict, status }) {
  const v = (verdict || status || '').toUpperCase();
  let badgeClass = 'badge-neutral';

  if (v === 'ACCEPT') badgeClass = 'badge-accept';
  else if (v === 'DROP') badgeClass = 'badge-drop';
  else if (v === 'REJECT') badgeClass = 'badge-reject';

  return <span className={`badge ${badgeClass}`}>{v || 'UNKNOWN'}</span>;
}
