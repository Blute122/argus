import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../store/AuthContext';
import { login as loginApi } from '../services/api';

export default function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const res = await loginApi(username, password);
      login(res.data.access_token, res.data.user);
      navigate('/dashboard');
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[var(--bg-primary)] relative overflow-hidden">
      {/* Animated background grid */}
      <div className="absolute inset-0 opacity-[0.03]"
        style={{
          backgroundImage: `linear-gradient(rgba(6,182,212,0.3) 1px, transparent 1px), linear-gradient(90deg, rgba(6,182,212,0.3) 1px, transparent 1px)`,
          backgroundSize: '40px 40px',
        }}
      />

      {/* Glow effects */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl" />
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-blue-500/5 rounded-full blur-3xl" />

      <div className="relative z-10 w-full max-w-md animate-fade-in">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-cyan-500 to-blue-600 mb-4 shadow-lg shadow-cyan-500/20">
            <span className="text-2xl font-bold text-white">SC</span>
          </div>
          <h1 className="text-2xl font-bold text-[var(--text-primary)] tracking-wide">SOC COMMAND CENTER</h1>
          <p className="text-sm text-[var(--text-muted)] mt-1 font-mono">Security Operations Simulator v1.0</p>
        </div>

        {/* Login card */}
        <div className="glass-card p-8">
          <div className="flex items-center gap-2 mb-6 pb-4 border-b border-[var(--border-color)]">
            <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
            <span className="text-xs text-[var(--text-muted)] font-mono">SYSTEM ONLINE — AWAITING AUTHENTICATION</span>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1.5 font-mono uppercase tracking-wider">Analyst ID</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="input-field font-mono"
                placeholder="Enter username"
                required
              />
            </div>
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1.5 font-mono uppercase tracking-wider">Access Key</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="input-field font-mono"
                placeholder="Enter password"
                required
              />
            </div>

            {error && (
              <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm font-mono">
                ⚠ {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="btn-primary w-full text-center disabled:opacity-50"
            >
              {loading ? 'AUTHENTICATING...' : 'ACCESS SYSTEM'}
            </button>
          </form>

          {/* Demo credentials */}
          <div className="mt-6 pt-4 border-t border-[var(--border-color)]">
            <p className="text-[10px] text-[var(--text-muted)] font-mono mb-2 uppercase tracking-wider">Demo Credentials</p>
            <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
              <div className="p-2 rounded bg-[var(--bg-input)] border border-[var(--border-color)]">
                <span className="text-[var(--accent-cyan)]">admin</span>
                <span className="text-[var(--text-muted)]"> / admin123</span>
              </div>
              <div className="p-2 rounded bg-[var(--bg-input)] border border-[var(--border-color)]">
                <span className="text-[var(--accent-cyan)]">analyst1</span>
                <span className="text-[var(--text-muted)]"> / analyst123</span>
              </div>
            </div>
          </div>
        </div>

        <p className="text-center text-[10px] text-[var(--text-muted)] mt-6 font-mono">
          CLASSIFIED — AUTHORIZED PERSONNEL ONLY
        </p>
      </div>
    </div>
  );
}
