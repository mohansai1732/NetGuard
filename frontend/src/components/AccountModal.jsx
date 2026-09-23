import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import Modal from './Modal';
import { KeyRound, Server, CheckCircle2, AlertCircle } from 'lucide-react';

export default function AccountModal({ isOpen, onClose, systemStatus }) {
  const { user, changePassword } = useAuth();
  const [activeTab, setActiveTab] = useState('password');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);

  const handlePasswordSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (newPassword.length < 8) {
      setError('New password must be at least 8 characters long.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('New passwords do not match.');
      return;
    }

    setLoading(true);
    try {
      await changePassword(currentPassword, newPassword);
      setSuccess('Password updated successfully.');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      setTimeout(() => {
        setSuccess('');
        onClose();
      }, 1500);
    } catch (err) {
      setError(err.message || 'Failed to update password');
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Account & System">
      <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid var(--border-color)', paddingBottom: '12px', marginBottom: '16px' }}>
        <button
          onClick={() => setActiveTab('password')}
          className={`btn ${activeTab === 'password' ? 'btn-secondary' : ''}`}
          style={{ background: activeTab === 'password' ? '#27272a' : 'transparent', border: 'none' }}
        >
          <KeyRound size={14} />
          <span>Change Password</span>
        </button>
        <button
          onClick={() => setActiveTab('system')}
          className={`btn ${activeTab === 'system' ? 'btn-secondary' : ''}`}
          style={{ background: activeTab === 'system' ? '#27272a' : 'transparent', border: 'none' }}
        >
          <Server size={14} />
          <span>Host Diagnostics</span>
        </button>
      </div>

      {activeTab === 'password' ? (
        <form onSubmit={handlePasswordSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          {error && (
            <div style={{ background: 'var(--verdict-drop-bg)', border: '1px solid var(--verdict-drop-border)', borderRadius: 'var(--radius-sm)', padding: '8px 12px', color: 'var(--verdict-drop-text)', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <AlertCircle size={15} />
              <span>{error}</span>
            </div>
          )}
          {success && (
            <div style={{ background: 'var(--verdict-accept-bg)', border: '1px solid var(--verdict-accept-border)', borderRadius: 'var(--radius-sm)', padding: '8px 12px', color: 'var(--verdict-accept-text)', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <CheckCircle2 size={15} />
              <span>{success}</span>
            </div>
          )}

          <div>
            <label className="label">Current Password</label>
            <input
              type="password"
              className="input"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              required
            />
          </div>

          <div>
            <label className="label">New Password (min 8 chars)</label>
            <input
              type="password"
              className="input"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
              minLength={8}
            />
          </div>

          <div>
            <label className="label">Confirm New Password</label>
            <input
              type="password"
              className="input"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '8px' }}>
            <button type="button" className="btn btn-secondary" onClick={onClose} disabled={loading}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? 'Saving...' : 'Update Password'}
            </button>
          </div>
        </form>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '0.82rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 10px', background: '#202024', borderRadius: 'var(--radius-sm)' }}>
            <span style={{ color: 'var(--text-muted)' }}>Host Operating System</span>
            <span className="mono">{systemStatus?.platform || process.platform || 'Unknown'}</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 10px', background: '#202024', borderRadius: 'var(--radius-sm)' }}>
            <span style={{ color: 'var(--text-muted)' }}>Linux Kernel Status</span>
            <span className="mono" style={{ color: systemStatus?.subsystems?.linux ? '#22c55e' : '#a1a1aa' }}>
              {systemStatus?.subsystems?.linux ? 'Active' : 'Non-Linux (Development)'}
            </span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 10px', background: '#202024', borderRadius: 'var(--radius-sm)' }}>
            <span style={{ color: 'var(--text-muted)' }}>nftables Binary</span>
            <span className="mono" style={{ color: systemStatus?.subsystems?.nftablesBinary ? '#22c55e' : '#a1a1aa' }}>
              {systemStatus?.subsystems?.nftablesBinary ? '/usr/sbin/nft' : 'Not installed'}
            </span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 10px', background: '#202024', borderRadius: 'var(--radius-sm)' }}>
            <span style={{ color: 'var(--text-muted)' }}>Database</span>
            <span className="mono">node:sqlite (WAL mode)</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 10px', background: '#202024', borderRadius: 'var(--radius-sm)' }}>
            <span style={{ color: 'var(--text-muted)' }}>Node.js Runtime</span>
            <span className="mono">{systemStatus?.nodeVersion || 'v24'}</span>
          </div>
        </div>
      )}
    </Modal>
  );
}
