import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import Modal from '../components/Modal';
import TableEmptyState from '../components/TableEmptyState';
import StatusBadge from '../components/StatusBadge';
import {
  Ban,
  Plus,
  Search,
  RefreshCw,
  CheckCircle2,
  AlertCircle,
  Unlock,
} from 'lucide-react';

export default function IpManagement() {
  const [blockedIps, setBlockedIps] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');

  // Add block modal state
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [ipInput, setIpInput] = useState('');
  const [reasonInput, setReasonInput] = useState('');
  const [formError, setFormError] = useState('');
  const [formLoading, setFormLoading] = useState(false);
  const [notice, setNotice] = useState('');

  // Unblock modal state
  const [ipToUnblock, setIpToUnblock] = useState(null);
  const [unblockLoading, setUnblockLoading] = useState(false);

  const fetchBlocklist = async () => {
    setLoading(true);
    try {
      const data = await api.ipBlocklist.list();
      setBlockedIps(data.blockedIps || []);
    } catch (err) {
      console.error('Failed to fetch blocklist:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBlocklist();
  }, []);

  const handleAddBlock = async (e) => {
    e.preventDefault();
    setFormError('');
    setFormLoading(true);

    try {
      await api.ipBlocklist.add(ipInput.trim(), reasonInput.trim() || undefined);
      setIsAddModalOpen(false);
      setIpInput('');
      setReasonInput('');
      setNotice(`Address ${ipInput.trim()} added to nftables @blocklist.`);
      setTimeout(() => setNotice(''), 4000);
      await fetchBlocklist();
    } catch (err) {
      setFormError(err.message || 'Failed to add IP to blocklist');
    } finally {
      setFormLoading(false);
    }
  };

  const handleUnblock = async () => {
    if (!ipToUnblock) return;
    setUnblockLoading(true);

    try {
      await api.ipBlocklist.remove(ipToUnblock.ip_or_cidr);
      setNotice(`Address ${ipToUnblock.ip_or_cidr} removed from @blocklist.`);
      setIpToUnblock(null);
      setTimeout(() => setNotice(''), 4000);
      await fetchBlocklist();
    } catch (err) {
      alert(`Error unblocking IP: ${err.message}`);
    } finally {
      setUnblockLoading(false);
    }
  };

  const filteredIps = blockedIps.filter((item) => {
    if (!searchTerm) return true;
    const q = searchTerm.toLowerCase();
    return (
      item.ip_or_cidr.toLowerCase().includes(q) ||
      (item.reason && item.reason.toLowerCase().includes(q))
    );
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Top Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <h1 style={{ fontSize: '1.25rem', fontWeight: 600, color: 'var(--text-main)', margin: 0 }}>
            Blocked IP Addresses
          </h1>
          <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', margin: '4px 0 0' }}>
            Direct packet dropping enforced via kernel set <code className="mono">@blocklist</code> before traversing rules.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button onClick={fetchBlocklist} className="btn btn-secondary">
            <RefreshCw size={14} className={loading ? 'spin' : ''} />
            <span>Reload</span>
          </button>
          <button onClick={() => setIsAddModalOpen(true)} className="btn btn-danger">
            <Plus size={15} />
            <span>Block IP Address</span>
          </button>
        </div>
      </div>

      {/* Notice Alert */}
      {notice && (
        <div
          style={{
            background: 'var(--accent-green-bg)',
            border: '1px solid var(--accent-green-border)',
            borderRadius: '6px',
            padding: '10px 14px',
            color: 'var(--accent-green-text)',
            fontSize: '0.8125rem',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
          }}
        >
          <CheckCircle2 size={16} />
          <span>{notice}</span>
        </div>
      )}

      {/* Search and Summary */}
      <div className="card" style={{ padding: '12px 16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ position: 'relative', width: '100%', maxWidth: '340px' }}>
          <input
            type="text"
            className="input"
            placeholder="Search by IP, subnet, or reason..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{ paddingLeft: '34px' }}
          />
          <Search size={14} color="var(--text-dim)" style={{ position: 'absolute', left: 11, top: 10 }} />
        </div>

        <div style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
          Total Blocked: <strong className="mono" style={{ color: 'var(--text-main)' }}>{blockedIps.length}</strong>
        </div>
      </div>

      {/* Blocked IPs Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th style={{ width: '80px' }}>Action</th>
                <th>Target IP / Subnet</th>
                <th>Reason</th>
                <th>Added By</th>
                <th>Blocked At</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <TableEmptyState
                  title="Querying kernel set..."
                  subtitle="Reading @blocklist elements from nftables"
                  colSpan={6}
                />
              ) : filteredIps.length === 0 ? (
                <TableEmptyState
                  title={searchTerm ? 'No matching blocked IPs' : 'No blocked addresses'}
                  subtitle={
                    searchTerm
                      ? 'No items match your search filter'
                      : 'Packets from blocked IPs are immediately dropped at the ingress/forward stage'
                  }
                  colSpan={6}
                />
              ) : (
                filteredIps.map((item) => (
                  <tr key={item.id || item.ip_or_cidr}>
                    <td>
                      <StatusBadge verdict="DROP" />
                    </td>
                    <td className="mono" style={{ color: 'var(--text-main)', fontWeight: 500, fontSize: '0.875rem' }}>
                      {item.ip_or_cidr}
                    </td>
                    <td style={{ color: 'var(--text-main)', fontSize: '0.8125rem' }}>
                      {item.reason || <span style={{ color: 'var(--text-dim)' }}>None specified</span>}
                    </td>
                    <td className="mono" style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                      {item.added_by || 'admin'}
                    </td>
                    <td className="mono" style={{ color: 'var(--text-dim)', fontSize: '0.75rem', whiteSpace: 'nowrap' }}>
                      {new Date(item.created_at).toLocaleString()}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        onClick={() => setIpToUnblock(item)}
                        className="btn btn-secondary btn-sm"
                        style={{ display: 'inline-flex', alignItems: 'center', gap: '5px' }}
                      >
                        <Unlock size={13} />
                        <span>Unblock</span>
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add IP Modal */}
      <Modal
        isOpen={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        title="Block IP Address or Subnet"
        maxWidth="480px"
      >
        {formError && (
          <div
            style={{
              background: 'var(--accent-red-bg)',
              border: '1px solid var(--accent-red-border)',
              borderRadius: '6px',
              padding: '10px 14px',
              marginBottom: '16px',
              color: 'var(--accent-red-text)',
              fontSize: '0.8125rem',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
            }}
          >
            <AlertCircle size={15} />
            <span>{formError}</span>
          </div>
        )}

        <form onSubmit={handleAddBlock} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div>
            <label className="label">IP Address or CIDR Subnet</label>
            <input
              type="text"
              className="input mono"
              placeholder="e.g. 203.0.113.88 or 198.51.100.0/24"
              value={ipInput}
              onChange={(e) => setIpInput(e.target.value)}
              required
              autoFocus
            />
            <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '4px', display: 'block' }}>
              Accepts standard IPv4, IPv6, or CIDR network prefixes.
            </span>
          </div>

          <div>
            <label className="label">Reason / Reference Note</label>
            <input
              type="text"
              className="input"
              placeholder="e.g. Excessive port scan attempts"
              value={reasonInput}
              onChange={(e) => setReasonInput(e.target.value)}
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '8px' }}>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => setIsAddModalOpen(false)}
              disabled={formLoading}
            >
              Cancel
            </button>
            <button type="submit" className="btn btn-danger" disabled={formLoading}>
              <Ban size={14} />
              <span>{formLoading ? 'Adding...' : 'Block Address'}</span>
            </button>
          </div>
        </form>
      </Modal>

      {/* Unblock Confirmation Modal */}
      <Modal
        isOpen={Boolean(ipToUnblock)}
        onClose={() => setIpToUnblock(null)}
        title="Confirm Removal from Blocklist"
        maxWidth="440px"
      >
        <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem', lineHeight: 1.5, marginBottom: '18px' }}>
          Are you sure you want to remove <strong className="mono" style={{ color: 'var(--text-main)' }}>{ipToUnblock?.ip_or_cidr}</strong> from the firewall blocklist?
          Inbound traffic from this IP will no longer be dropped before rule processing.
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => setIpToUnblock(null)}
            disabled={unblockLoading}
          >
            Cancel
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={handleUnblock}
            disabled={unblockLoading}
          >
            {unblockLoading ? 'Removing...' : 'Confirm Unblock'}
          </button>
        </div>
      </Modal>
    </div>
  );
}
