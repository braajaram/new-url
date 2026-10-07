import React, { useState, useEffect } from 'react';
import { Settings, Key, Shield, Bell, Check, Save } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const SettingsPage: React.FC = () => {
  const { user } = useAuth();
  const [providers, setProviders] = useState<any>(null);
  const [systemSettings, setSystemSettings] = useState<any>(null);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  // Form states
  const [vtKey, setVtKey] = useState('');
  const [vtEnabled, setVtEnabled] = useState(false);

  const [gsbKey, setGsbKey] = useState('');
  const [gsbEnabled, setGsbEnabled] = useState(false);

  const [urlhausKey, setUrlhausKey] = useState('');
  const [urlhausEnabled, setUrlhausEnabled] = useState(false);

  const loadSettings = async () => {
    try {
      const res = await fetch('/api/settings');
      if (res.ok) {
        const data = await res.json();
        setProviders(data.providers);
        setSystemSettings(data.systemSettings);
        setVtEnabled(data.providers.virusTotal.enabled);
        setGsbEnabled(data.providers.googleSafeBrowsing.enabled);
        setUrlhausEnabled(data.providers.urlhaus.enabled);
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    loadSettings();
  }, []);

  const saveProvider = async (provider: string, apiKey: string, enabled: boolean) => {
    try {
      const res = await fetch('/api/settings/provider', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider, apiKey, enabled })
      });
      if (res.ok) {
        setStatusMsg(`${provider} configuration updated successfully.`);
        setTimeout(() => setStatusMsg(null), 3000);
        await loadSettings();
      }
    } catch (e) {
      console.error(e);
    }
  };

  const saveSystem = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch('/api/settings/system', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(systemSettings)
      });
      if (res.ok) {
        setStatusMsg('System settings persisted.');
        setTimeout(() => setStatusMsg(null), 3000);
        await loadSettings();
      }
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6 font-mono">
      <div>
        <div className="flex items-center space-x-2">
          <h1 className="text-xl font-bold text-white tracking-wide">SOC Platform Settings & API Configuration</h1>
          <span className="px-2 py-0.5 text-[10px] bg-red-950 text-red-400 border border-red-800 rounded">
            CONFIG CENTER
          </span>
        </div>
        <p className="text-xs text-gray-400 mt-1 font-sans">
          Manage real external Threat Intelligence API keys, SSRF scanning thresholds, and notification rules.
        </p>
      </div>

      {statusMsg && (
        <div className="p-3 rounded-lg bg-emerald-950/60 border border-emerald-800 text-xs text-emerald-300">
          {statusMsg}
        </div>
      )}

      {/* External Threat Intelligence Keys */}
      <div className="p-6 rounded-xl bg-[#0e1422] border border-gray-800 space-y-6">
        <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center space-x-2">
          <Key size={16} className="text-red-400" />
          <span>External Threat Intelligence Feeds</span>
        </h3>

        <div className="space-y-4">
          {/* VirusTotal */}
          <div className="p-4 rounded-lg bg-gray-900 border border-gray-800 space-y-3">
            <div className="flex justify-between items-center">
              <div>
                <span className="font-bold text-white text-xs">VirusTotal v3 Intelligence API</span>
                <div className="text-[10px] text-gray-500">
                  Status: {providers?.virusTotal?.isConfigured ? 'Configured' : 'Not Configured'}
                </div>
              </div>
              <label className="flex items-center space-x-2 text-xs">
                <input
                  type="checkbox"
                  checked={vtEnabled}
                  onChange={(e) => setVtEnabled(e.target.checked)}
                />
                <span className="text-gray-300">Active</span>
              </label>
            </div>
            <div className="flex gap-2">
              <input
                type="password"
                value={vtKey}
                onChange={(e) => setVtKey(e.target.value)}
                placeholder={providers?.virusTotal?.maskedKey || 'Enter VirusTotal API Key...'}
                className="flex-1 bg-[#131b2c] border border-gray-700 text-xs text-white px-3 py-2 rounded focus:outline-none"
              />
              <button
                onClick={() => saveProvider('virusTotal', vtKey, vtEnabled)}
                className="px-3 py-2 rounded bg-red-600 hover:bg-red-500 text-white text-xs font-semibold"
              >
                Save
              </button>
            </div>
          </div>

          {/* Google Safe Browsing */}
          <div className="p-4 rounded-lg bg-gray-900 border border-gray-800 space-y-3">
            <div className="flex justify-between items-center">
              <div>
                <span className="font-bold text-white text-xs">Google Safe Browsing v4 API</span>
                <div className="text-[10px] text-gray-500">
                  Status: {providers?.googleSafeBrowsing?.isConfigured ? 'Configured' : 'Not Configured'}
                </div>
              </div>
              <label className="flex items-center space-x-2 text-xs">
                <input
                  type="checkbox"
                  checked={gsbEnabled}
                  onChange={(e) => setGsbEnabled(e.target.checked)}
                />
                <span className="text-gray-300">Active</span>
              </label>
            </div>
            <div className="flex gap-2">
              <input
                type="password"
                value={gsbKey}
                onChange={(e) => setGsbKey(e.target.value)}
                placeholder={providers?.googleSafeBrowsing?.maskedKey || 'Enter Google Safe Browsing Key...'}
                className="flex-1 bg-[#131b2c] border border-gray-700 text-xs text-white px-3 py-2 rounded focus:outline-none"
              />
              <button
                onClick={() => saveProvider('googleSafeBrowsing', gsbKey, gsbEnabled)}
                className="px-3 py-2 rounded bg-red-600 hover:bg-red-500 text-white text-xs font-semibold"
              >
                Save
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* System & Privacy Settings */}
      {systemSettings && (
        <form onSubmit={saveSystem} className="p-6 rounded-xl bg-[#0e1422] border border-gray-800 space-y-4">
          <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center space-x-2">
            <Shield size={16} className="text-blue-400" />
            <span>Inspection Engine & Privacy Controls</span>
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div>
              <label className="text-gray-400 block mb-1">Max HTTP Redirect Hops</label>
              <input
                type="number"
                value={systemSettings.maxRedirects}
                onChange={(e) => setSystemSettings({ ...systemSettings, maxRedirects: Number(e.target.value) })}
                className="w-full bg-[#131b2c] border border-gray-700 p-2 rounded text-white"
              />
            </div>
            <div>
              <label className="text-gray-400 block mb-1">Scan Timeout (ms)</label>
              <input
                type="number"
                value={systemSettings.scanTimeoutMs}
                onChange={(e) => setSystemSettings({ ...systemSettings, scanTimeoutMs: Number(e.target.value) })}
                className="w-full bg-[#131b2c] border border-gray-700 p-2 rounded text-white"
              />
            </div>
          </div>

          <div className="pt-2 space-y-2 text-xs">
            <label className="flex items-center space-x-2 cursor-pointer">
              <input
                type="checkbox"
                checked={systemSettings.privacyMode}
                onChange={(e) => setSystemSettings({ ...systemSettings, privacyMode: e.target.checked })}
              />
              <span className="text-gray-300">Privacy Mode (Do not record scanned targets in database log)</span>
            </label>
            <label className="flex items-center space-x-2 cursor-pointer">
              <input
                type="checkbox"
                checked={systemSettings.autoAlerts}
                onChange={(e) => setSystemSettings({ ...systemSettings, autoAlerts: e.target.checked })}
              />
              <span className="text-gray-300">Automatic SOC Incident Generation on Malicious Verdicts</span>
            </label>
          </div>

          <div className="pt-2">
            <button
              type="submit"
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded flex items-center space-x-1.5"
            >
              <Save size={14} />
              <span>Save System Settings</span>
            </button>
          </div>
        </form>
      )}
    </div>
  );
};
