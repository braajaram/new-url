import React, { useState } from 'react';
import { ShieldAlert, ArrowRight, Lock, Mail, User } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const LoginPage: React.FC<{ onSwitchToRegister: () => void; onSuccess: () => void }> = ({ onSwitchToRegister, onSuccess }) => {
  const { login } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    const res = await login(email, password);
    setLoading(false);
    if (res.success) {
      onSuccess();
    } else {
      setError(res.error || 'Login failed');
    }
  };

  return (
    <div className="min-h-[80vh] flex items-center justify-center p-4">
      <div className="w-full max-w-md p-8 rounded-xl bg-[#0e1422] border border-gray-800 shadow-2xl space-y-6">
        <div className="text-center space-y-2">
          <div className="w-10 h-10 rounded-lg bg-red-950 border border-red-800 flex items-center justify-center text-red-400 mx-auto">
            <ShieldAlert size={22} />
          </div>
          <h2 className="text-xl font-bold text-white tracking-wide">SOC Analyst Authentication</h2>
          <p className="text-xs text-gray-400">Log in to access live threat feeds and automated continuous polling.</p>
        </div>

        {error && (
          <div className="p-3 rounded-lg bg-red-950/60 border border-red-800 text-xs font-mono text-red-300">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="text-xs text-gray-400 block mb-1">Email Address</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="admin@threatanalyze.internal"
              required
              className="w-full bg-[#131b2c] border border-gray-700 text-sm text-white px-3 py-2.5 rounded focus:outline-none focus:border-red-500 font-mono"
            />
          </div>
          <div>
            <label className="text-xs text-gray-400 block mb-1">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              required
              className="w-full bg-[#131b2c] border border-gray-700 text-sm text-white px-3 py-2.5 rounded focus:outline-none focus:border-red-500 font-mono"
            />
          </div>

          <div className="p-2.5 rounded bg-gray-900 border border-gray-800 text-[11px] text-gray-400 font-mono">
            Default Admin: <span className="text-gray-200">admin@threatanalyze.internal</span> / <span className="text-gray-200">AdminPassword123!</span>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 bg-red-600 hover:bg-red-500 text-white font-semibold text-xs rounded transition-colors flex items-center justify-center space-x-2"
          >
            <span>{loading ? 'Authenticating...' : 'Sign In To SOC'}</span>
            <ArrowRight size={14} />
          </button>
        </form>

        <div className="text-center text-xs text-gray-500">
          Don't have an officer account?{' '}
          <button onClick={onSwitchToRegister} className="text-red-400 hover:underline">
            Register Account
          </button>
        </div>
      </div>
    </div>
  );
};

export const RegisterPage: React.FC<{ onSwitchToLogin: () => void; onSuccess: () => void }> = ({ onSwitchToLogin, onSuccess }) => {
  const { register } = useAuth();
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    const res = await register(name, email, password);
    setLoading(false);
    if (res.success) {
      onSuccess();
    } else {
      setError(res.error || 'Registration failed');
    }
  };

  return (
    <div className="min-h-[80vh] flex items-center justify-center p-4">
      <div className="w-full max-w-md p-8 rounded-xl bg-[#0e1422] border border-gray-800 shadow-2xl space-y-6">
        <div className="text-center space-y-2">
          <div className="w-10 h-10 rounded-lg bg-red-950 border border-red-800 flex items-center justify-center text-red-400 mx-auto">
            <User size={22} />
          </div>
          <h2 className="text-xl font-bold text-white tracking-wide">Register Security Analyst</h2>
          <p className="text-xs text-gray-400">Join the Threat Analyze defense monitoring team.</p>
        </div>

        {error && (
          <div className="p-3 rounded-lg bg-red-950/60 border border-red-800 text-xs font-mono text-red-300">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="text-xs text-gray-400 block mb-1">Full Name / Callsign</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. John Doe / Lead Analyst"
              required
              className="w-full bg-[#131b2c] border border-gray-700 text-sm text-white px-3 py-2.5 rounded focus:outline-none focus:border-red-500 font-mono"
            />
          </div>
          <div>
            <label className="text-xs text-gray-400 block mb-1">Work Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="analyst@threatanalyze.internal"
              required
              className="w-full bg-[#131b2c] border border-gray-700 text-sm text-white px-3 py-2.5 rounded focus:outline-none focus:border-red-500 font-mono"
            />
          </div>
          <div>
            <label className="text-xs text-gray-400 block mb-1">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              required
              className="w-full bg-[#131b2c] border border-gray-700 text-sm text-white px-3 py-2.5 rounded focus:outline-none focus:border-red-500 font-mono"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 bg-red-600 hover:bg-red-500 text-white font-semibold text-xs rounded transition-colors flex items-center justify-center space-x-2"
          >
            <span>{loading ? 'Registering...' : 'Complete Registration'}</span>
            <ArrowRight size={14} />
          </button>
        </form>

        <div className="text-center text-xs text-gray-500">
          Already registered?{' '}
          <button onClick={onSwitchToLogin} className="text-red-400 hover:underline">
            Log In
          </button>
        </div>
      </div>
    </div>
  );
};
