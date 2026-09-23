import React, { createContext, useContext, useState, useEffect } from 'react';
import { api, setUnauthorizedHandler } from '../services/api';
import { wsClient } from '../services/websocket';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => localStorage.getItem('netguard_token') || null);
  const [user, setUser] = useState(() => {
    try {
      const saved = localStorage.getItem('netguard_user');
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });
  const [loading, setLoading] = useState(true);

  const logout = () => {
    localStorage.removeItem('netguard_token');
    localStorage.removeItem('netguard_user');
    setToken(null);
    setUser(null);
    wsClient.disconnect();
  };

  useEffect(() => {
    // Register single 401 interceptor callback
    setUnauthorizedHandler(() => {
      logout();
    });

    if (token) {
      wsClient.connect();
    } else {
      wsClient.disconnect();
    }

    setLoading(false);
  }, [token]);

  const setAuthenticatedSession = (newToken, newUser) => {
    localStorage.setItem('netguard_token', newToken);
    localStorage.setItem('netguard_user', JSON.stringify(newUser));
    setToken(newToken);
    setUser(newUser);
    wsClient.connect();
  };

  const login = async (username, password) => {
    const res = await api.auth.login(username, password);
    // If mustChangePassword is true, return token & user without completing session yet
    // so Login.jsx can transition inline
    if (res.user.mustChangePassword) {
      return { mustChangePassword: true, tempToken: res.token, user: res.user };
    }
    setAuthenticatedSession(res.token, res.user);
    return { mustChangePassword: false, user: res.user };
  };

  const completeInitialPasswordChange = async (tempToken, currentPassword, newPassword) => {
    // Temporarily set token in localStorage for request header
    localStorage.setItem('netguard_token', tempToken);
    await api.auth.changePassword(currentPassword, newPassword);
    const profile = await api.auth.getMe();
    setAuthenticatedSession(tempToken, profile);
    return profile;
  };

  const changePassword = async (currentPassword, newPassword) => {
    await api.auth.changePassword(currentPassword, newPassword);
    const updatedUser = { ...user, mustChangePassword: false };
    localStorage.setItem('netguard_user', JSON.stringify(updatedUser));
    setUser(updatedUser);
  };

  return (
    <AuthContext.Provider
      value={{
        token,
        user,
        isAuthenticated: Boolean(token),
        loading,
        login,
        completeInitialPasswordChange,
        logout,
        changePassword,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
