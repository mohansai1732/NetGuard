import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import TableEmptyState from '../components/TableEmptyState';
import {
  Search,
  RefreshCw,
} from 'lucide-react';

export default function Logs() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [actionFilter, setActionFilter] = useState('ALL');
  const [searchTerm, setSearchTerm] = useState('');

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const params = {};
      if (actionFilter !== 'ALL') params.action = actionFilter;
      if (searchTerm) params.search = searchTerm;
      const data = await api.auditLogs.list(params);
      setLogs(data.logs || []);
    } catch (err) {
      console.error('Failed to fetch audit logs:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [actionFilter]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    fetchLogs();
  };

  const getActionBadge = (action) => {
    switch (action) {
      case 'RULE_ADD':
        return <span className="badge badge-accept">RULE_ADD</span>;
      case 'RULE_DELETE':
        return <span className="badge badge-drop">RULE_DELETE</span>;
      case 'IP_BLOCK':
        return <span className="badge badge-drop">IP_BLOCK</span>;
      case 'IP_UNBLOCK':
        return <span className="badge badge-neutral">IP_UNBLOCK</span>;
      case 'LOGIN_SUCCESS':
        return <span className="badge badge-neutral">LOGIN</span>;
      case 'PASSWORD_CHANGE':
        return <span className="badge badge-neutral">PASSWD_CHG</span>;
      default:
        return <span className="badge badge-neutral">{action}</span>;
    }
  };

  const formatDetails = (details) => {
    if (!details) return <span style={{ color: 'var(--text-dim)' }}>—</span>;
    if (typeof details === 'object') {
      return (
        <pre
          className="mono"
          style={{
            margin: 0,
            fontSize: '0.75rem',
            color: 'var(--text-muted)',
            background: 'var(--bg-main)',
            border: '1px solid var(--border-subtle)',
            padding: '6px 10px',
            borderRadius: '4px',
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-all',
          }}
        >
          {JSON.stringify(details, null, 2)}
        </pre>
      );
    }
    return <span style={{ fontSize: '0.8125rem', color: 'var(--text-main)' }}>{String(details)}</span>;
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Top Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <h1 style={{ fontSize: '1.25rem', fontWeight: 600, color: 'var(--text-main)', margin: 0 }}>
            Audit Trail
          </h1>
          <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', margin: '4px 0 0' }}>
            Administrative action logs: rule additions, deletions, IP blocklist modifications, and authentication events.
          </p>
        </div>

        <button onClick={fetchLogs} className="btn btn-secondary">
          <RefreshCw size={14} className={loading ? 'spin' : ''} />
          <span>Reload</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="card" style={{ padding: '12px 16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
        <form onSubmit={handleSearchSubmit} style={{ display: 'flex', alignItems: 'center', gap: '8px', flex: 1, minWidth: '260px' }}>
          <div style={{ position: 'relative', width: '100%', maxWidth: '340px' }}>
            <input
              type="text"
              className="input"
              placeholder="Search actions, operators, details..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{ paddingLeft: '34px' }}
            />
            <Search size={14} color="var(--text-dim)" style={{ position: 'absolute', left: 11, top: 10 }} />
          </div>
          <button type="submit" className="btn btn-secondary btn-sm">
            Search
          </button>
        </form>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>Action:</span>
          <select
            className="select"
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            style={{ width: 'auto', padding: '5px 10px', fontSize: '0.8125rem' }}
          >
            <option value="ALL">All Actions</option>
            <option value="RULE_ADD">RULE_ADD</option>
            <option value="RULE_DELETE">RULE_DELETE</option>
            <option value="IP_BLOCK">IP_BLOCK</option>
            <option value="IP_UNBLOCK">IP_UNBLOCK</option>
            <option value="LOGIN_SUCCESS">LOGIN_SUCCESS</option>
            <option value="PASSWORD_CHANGE">PASSWORD_CHANGE</option>
          </select>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th style={{ width: '170px' }}>Timestamp</th>
                <th style={{ width: '110px' }}>Operator</th>
                <th style={{ width: '130px' }}>Action</th>
                <th>Change Details</th>
                <th style={{ width: '90px', textAlign: 'right' }}>Status</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <TableEmptyState
                  title="Loading audit trail..."
                  subtitle="Querying audit records from local database"
                  colSpan={5}
                />
              ) : logs.length === 0 ? (
                <TableEmptyState
                  title={searchTerm || actionFilter !== 'ALL' ? 'No matching audit records' : 'No audit entries recorded'}
                  subtitle={
                    searchTerm || actionFilter !== 'ALL'
                      ? 'Try modifying your search query or action filter'
                      : 'Administrative actions will automatically appear here as they occur'
                  }
                  colSpan={5}
                />
              ) : (
                logs.map((log) => (
                  <tr key={log.id}>
                    <td className="mono" style={{ color: 'var(--text-dim)', fontSize: '0.75rem', whiteSpace: 'nowrap' }}>
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td>
                      <span className="mono" style={{ color: 'var(--text-main)', fontWeight: 500, fontSize: '0.8125rem' }}>
                        {log.admin_username}
                      </span>
                    </td>
                    <td>{getActionBadge(log.action)}</td>
                    <td style={{ maxWidth: '440px' }}>{formatDetails(log.details)}</td>
                    <td style={{ textAlign: 'right' }}>
                      <span
                        className={`badge ${log.status === 'SUCCESS' ? 'badge-accept' : 'badge-drop'}`}
                      >
                        {log.status}
                      </span>
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
