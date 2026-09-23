import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import Modal from '../components/Modal';
import StatusBadge from '../components/StatusBadge';
import TableEmptyState from '../components/TableEmptyState';
import { Plus, Trash2, RefreshCw, Search, AlertCircle, CheckCircle2 } from 'lucide-react';

export default function Rules() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [chainFilter, setChainFilter] = useState('ALL');
  const [actionFilter, setActionFilter] = useState('ALL');

  // Add rule modal state
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [formData, setFormData] = useState({
    chain: 'input',
    protocol: 'tcp',
    src_ip: '',
    dst_ip: '',
    port: '',
    action: 'DROP',
    comment: '',
  });
  const [formError, setFormError] = useState('');
  const [formLoading, setFormLoading] = useState(false);
  const [notice, setNotice] = useState('');

  // Delete modal state
  const [ruleToDelete, setRuleToDelete] = useState(null);
  const [deleteLoading, setDeleteLoading] = useState(false);

  const fetchRules = async () => {
    setLoading(true);
    try {
      const data = await api.rules.list();
      setRules(data.rules || []);
    } catch (err) {
      console.error('Failed to fetch rules:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const handleAddRule = async (e) => {
    e.preventDefault();
    setFormError('');
    setFormLoading(true);

    try {
      await api.rules.add({
        chain: formData.chain,
        protocol: formData.protocol,
        src_ip: formData.src_ip.trim() || null,
        dst_ip: formData.dst_ip.trim() || null,
        port: formData.port.trim() || null,
        action: formData.action,
        comment: formData.comment.trim() || undefined,
      });

      setIsAddModalOpen(false);
      setFormData({
        chain: 'input',
        protocol: 'tcp',
        src_ip: '',
        dst_ip: '',
        port: '',
        action: 'DROP',
        comment: '',
      });
      setNotice('Firewall rule applied successfully.');
      setTimeout(() => setNotice(''), 3000);
      await fetchRules();
    } catch (err) {
      setFormError(err.message || 'Failed to add rule');
    } finally {
      setFormLoading(false);
    }
  };

  const handleDeleteRule = async () => {
    if (!ruleToDelete) return;
    setDeleteLoading(true);
    try {
      await api.rules.delete(ruleToDelete.handle);
      setRuleToDelete(null);
      setNotice(`Rule #${ruleToDelete.handle} deleted.`);
      setTimeout(() => setNotice(''), 3000);
      await fetchRules();
    } catch (err) {
      alert(`Error deleting rule: ${err.message}`);
    } finally {
      setDeleteLoading(false);
    }
  };

  const filteredRules = rules.filter((r) => {
    if (chainFilter !== 'ALL' && r.chain !== chainFilter) return false;
    if (actionFilter !== 'ALL' && r.action !== actionFilter) return false;
    if (searchTerm) {
      const q = searchTerm.toLowerCase();
      const matchSrc = r.src_ip && r.src_ip.toLowerCase().includes(q);
      const matchPort = r.port && String(r.port).includes(q);
      const matchComment = r.comment && r.comment.toLowerCase().includes(q);
      const matchHandle = String(r.handle).includes(q);
      if (!matchSrc && !matchPort && !matchComment && !matchHandle) return false;
    }
    return true;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h1 style={{ fontSize: '1.3rem', fontWeight: 600, color: 'var(--text-main)', margin: 0 }}>
            Firewall Rules
          </h1>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', margin: '2px 0 0' }}>
            Filter rules configured in nftables chains.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button onClick={fetchRules} className="btn btn-secondary btn-sm" disabled={loading}>
            <RefreshCw size={13} className={loading ? 'spin' : ''} />
            <span>Reload</span>
          </button>
          <button onClick={() => setIsAddModalOpen(true)} className="btn btn-primary btn-sm">
            <Plus size={14} />
            <span>Add Rule</span>
          </button>
        </div>
      </div>

      {notice && (
        <div style={{ background: 'var(--verdict-accept-bg)', border: '1px solid var(--verdict-accept-border)', borderRadius: 'var(--radius-sm)', padding: '10px 14px', color: 'var(--verdict-accept-text)', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <CheckCircle2 size={16} />
          <span>{notice}</span>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="card" style={{ padding: '12px 14px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
        <div style={{ position: 'relative', width: '100%', maxWidth: '300px' }}>
          <input
            type="text"
            className="input"
            placeholder="Filter rules..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{ paddingLeft: '32px' }}
          />
          <Search size={14} color="var(--text-dim)" style={{ position: 'absolute', left: 10, top: 9 }} />
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '0.8rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ color: 'var(--text-dim)' }}>Chain:</span>
            <select
              className="select"
              value={chainFilter}
              onChange={(e) => setChainFilter(e.target.value)}
              style={{ width: 'auto', padding: '4px 8px' }}
            >
              <option value="ALL">All</option>
              <option value="input">input</option>
              <option value="forward">forward</option>
            </select>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ color: 'var(--text-dim)' }}>Verdict:</span>
            <select
              className="select"
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              style={{ width: 'auto', padding: '4px 8px' }}
            >
              <option value="ALL">All</option>
              <option value="ACCEPT">ACCEPT</option>
              <option value="DROP">DROP</option>
              <option value="REJECT">REJECT</option>
            </select>
          </div>
        </div>
      </div>

      {/* Rules Table */}
      <div className="card" style={{ overflow: 'hidden' }}>
        <div className="data-table-container" style={{ border: 'none', borderRadius: 0 }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Handle</th>
                <th>Chain</th>
                <th>Protocol</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Port</th>
                <th>Verdict</th>
                <th>Comment</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredRules.length === 0 ? (
                <TableEmptyState
                  title={loading ? 'Loading rules...' : 'No rules match filter criteria'}
                  colSpan={9}
                />
              ) : (
                filteredRules.map((rule) => (
                  <tr key={rule.handle}>
                    <td className="mono" style={{ color: 'var(--text-dim)' }}>
                      #{rule.handle}
                    </td>
                    <td className="mono">{rule.chain}</td>
                    <td>
                      <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {rule.protocol.toUpperCase()}
                      </span>
                    </td>
                    <td className="mono">{rule.src_ip || 'any'}</td>
                    <td className="mono" style={{ color: 'var(--text-dim)' }}>{rule.dst_ip || 'any'}</td>
                    <td className="mono">{rule.port || 'any'}</td>
                    <td>
                      <StatusBadge verdict={rule.action} />
                    </td>
                    <td style={{ color: 'var(--text-dim)', maxWidth: '240px' }}>
                      {rule.comment || '—'}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        onClick={() => setRuleToDelete(rule)}
                        className="btn btn-danger btn-sm"
                        title="Delete rule"
                      >
                        <Trash2 size={12} />
                        <span>Delete</span>
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Rule Modal */}
      <Modal isOpen={isAddModalOpen} onClose={() => setIsAddModalOpen(false)} title="New Firewall Rule">
        {formError && (
          <div style={{ background: 'var(--verdict-drop-bg)', border: '1px solid var(--verdict-drop-border)', borderRadius: 'var(--radius-sm)', padding: '8px 12px', color: 'var(--verdict-drop-text)', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
            <AlertCircle size={15} />
            <span>{formError}</span>
          </div>
        )}

        <form onSubmit={handleAddRule} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
            <div>
              <label className="label">Chain</label>
              <select
                className="select"
                value={formData.chain}
                onChange={(e) => setFormData({ ...formData, chain: e.target.value })}
                required
              >
                <option value="input">input</option>
                <option value="forward">forward</option>
              </select>
            </div>
            <div>
              <label className="label">Protocol</label>
              <select
                className="select"
                value={formData.protocol}
                onChange={(e) => setFormData({ ...formData, protocol: e.target.value })}
                required
              >
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="icmp">ICMP</option>
                <option value="any">ANY</option>
              </select>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
            <div>
              <label className="label">Source IP / CIDR</label>
              <input
                type="text"
                className="input mono"
                placeholder="e.g. 198.51.100.99"
                value={formData.src_ip}
                onChange={(e) => setFormData({ ...formData, src_ip: e.target.value })}
              />
            </div>
            <div>
              <label className="label">Port</label>
              <input
                type="text"
                className="input mono"
                placeholder="e.g. 80 or 80-443"
                value={formData.port}
                onChange={(e) => setFormData({ ...formData, port: e.target.value })}
              />
            </div>
          </div>

          <div>
            <label className="label">Verdict</label>
            <select
              className="select"
              value={formData.action}
              onChange={(e) => setFormData({ ...formData, action: e.target.value })}
              required
            >
              <option value="DROP">DROP</option>
              <option value="ACCEPT">ACCEPT</option>
              <option value="REJECT">REJECT</option>
            </select>
          </div>

          <div>
            <label className="label">Comment</label>
            <input
              type="text"
              className="input"
              placeholder="Rule description or ticket reference"
              value={formData.comment}
              onChange={(e) => setFormData({ ...formData, comment: e.target.value })}
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
            <button type="submit" className="btn btn-primary" disabled={formLoading}>
              {formLoading ? 'Applying...' : 'Apply Rule'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Delete Rule Confirmation Modal */}
      <Modal isOpen={Boolean(ruleToDelete)} onClose={() => setRuleToDelete(null)} title="Delete Rule">
        <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem', lineHeight: 1.5, marginBottom: '16px' }}>
          Delete rule <strong className="mono">#{ruleToDelete?.handle}</strong> from chain <strong className="mono">{ruleToDelete?.chain}</strong>?
        </div>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
          <button type="button" className="btn btn-secondary" onClick={() => setRuleToDelete(null)} disabled={deleteLoading}>
            Cancel
          </button>
          <button type="button" className="btn btn-danger" onClick={handleDeleteRule} disabled={deleteLoading}>
            {deleteLoading ? 'Deleting...' : 'Confirm'}
          </button>
        </div>
      </Modal>
    </div>
  );
}
