// NetGuard API Client Service
const BASE_URL = '/api';

let onUnauthorizedCallback = null;

export function setUnauthorizedHandler(handler) {
  onUnauthorizedCallback = handler;
}

function getAuthHeader() {
  const token = localStorage.getItem('netguard_token');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function request(endpoint, options = {}) {
  const url = `${BASE_URL}${endpoint}`;
  const headers = {
    'Content-Type': 'application/json',
    ...getAuthHeader(),
    ...options.headers,
  };

  const response = await fetch(url, { ...options, headers });

  if (response.status === 401) {
    if (onUnauthorizedCallback) {
      onUnauthorizedCallback();
    }
  }

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const errorMsg = data.error || `HTTP ${response.status}: Request failed`;
    throw new Error(errorMsg);
  }

  return data;
}

export const api = {
  auth: {
    login: (username, password) =>
      request('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      }),
    changePassword: (currentPassword, newPassword) =>
      request('/auth/change-password', {
        method: 'POST',
        body: JSON.stringify({ currentPassword, newPassword }),
      }),
    getMe: () => request('/auth/me'),
  },

  stats: {
    getSummary: () => request('/stats/summary'),
    getSystemStatus: () => request('/stats/system'),
  },

  logs: {
    getRecent: (limit = 30) => request(`/logs/recent?limit=${limit}`),
  },

  rules: {
    list: () => request('/rules'),
    add: (ruleData) =>
      request('/rules', {
        method: 'POST',
        body: JSON.stringify(ruleData),
      }),
    update: (handle, ruleData) =>
      request(`/rules/${handle}`, {
        method: 'PUT',
        body: JSON.stringify(ruleData),
      }),
    delete: (handle) =>
      request(`/rules/${handle}`, {
        method: 'DELETE',
      }),
  },

  ipBlocklist: {
    list: () => request('/ip-blocklist'),
    add: (ip, reason) =>
      request('/ip-blocklist', {
        method: 'POST',
        body: JSON.stringify({ ip, reason }),
      }),
    remove: (ip) =>
      request(`/ip-blocklist/${encodeURIComponent(ip)}`, {
        method: 'DELETE',
      }),
  },

  auditLogs: {
    list: (params = {}) => {
      const query = new URLSearchParams(params).toString();
      return request(`/audit-logs${query ? `?${query}` : ''}`);
    },
  },
};
