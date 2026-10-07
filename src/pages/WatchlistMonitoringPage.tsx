import React, { useState, useEffect } from 'react';
import { Bell, Activity, Plus, Trash2, Play, Pause, RefreshCw, CheckCircle, AlertTriangle } from 'lucide-react';
import { WatchlistItem, MonitoringJob } from '../types/threat';

export const WatchlistMonitoringPage: React.FC = () => {
  const [watchlist, setWatchlist] = useState<WatchlistItem[]>([]);
  const [jobs, setJobs] = useState<MonitoringJob[]>([]);
  const [targetInput, setTargetInput] = useState('');
  const [targetType, setTargetType] = useState<'DOMAIN' | 'URL' | 'IP'>('DOMAIN');
  const [freq, setFreq] = useState<'15m' | '30m' | '1h' | '6h' | '24h'>('1h');
  const [loading, setLoading] = useState(false);

  const loadData = async () => {
    try {
      const [wRes, mRes] = await Promise.all([
        fetch('/api/watchlist'),
        fetch('/api/monitoring')
      ]);
      if (wRes.ok) setWatchlist(await wRes.json());
      if (mRes.ok) setJobs(await mRes.json());
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetInput.trim()) return;

    setLoading(true);
    try {
      await fetch('/api/watchlist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: targetInput.trim(), type: targetType, frequency: freq })
      });

      // Also create automated monitoring job
      await fetch('/api/monitoring', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: targetInput.trim(), intervalMinutes: 60, type: targetType })
      });

      setTargetInput('');
      await loadData();
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  const handleRemove = async (id: string) => {
    try {
      await fetch(`/api/watchlist/${id}`, { method: 'DELETE' });
      await loadData();
    } catch (e) {
      console.error(e);
    }
  };

  const handleTriggerJob = async (jobId: string) => {
    try {
      await fetch(`/api/monitoring/${jobId}/run`, { method: 'POST' });
      await loadData();
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      <div>
        <div className="flex items-center space-x-2">
          <h1 className="text-xl font-bold text-white tracking-wide">SOC Watchlist & Continuous Telemetry Polling</h1>
          <span className="px-2 py-0.5 text-[10px] font-mono bg-amber-950 text-amber-400 border border-amber-800 rounded">
            PERSISTED TARGETS
          </span>
        </div>
        <p className="text-xs text-gray-400 mt-1">
          Monitor sensitive infrastructure for DNS changes, certificate expiration, and emerging reputation degradation.
        </p>
      </div>

      <div className="p-5 rounded-xl bg-[#0e1422] border border-gray-800">
        <form onSubmit={handleAdd} className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            value={targetInput}
            onChange={(e) => setTargetInput(e.target.value)}
            placeholder="Add Domain or IP to Watchlist (e.g. auth.internal.org)..."
            className="flex-1 bg-[#131b2c] border border-gray-700 text-sm text-gray-100 placeholder-gray-500 px-4 py-2.5 rounded-lg focus:outline-none focus:border-amber-500 font-mono"
          />
          <select
            value={targetType}
            onChange={(e: any) => setTargetType(e.target.value)}
            className="bg-[#131b2c] border border-gray-700 text-xs text-gray-200 px-3 py-2.5 rounded-lg font-mono"
          >
            <option value="DOMAIN">DOMAIN</option>
            <option value="URL">URL</option>
            <option value="IP">IP</option>
          </select>
          <button
            type="submit"
            disabled={loading || !targetInput.trim()}
            className="px-5 py-2.5 rounded-lg bg-amber-600 hover:bg-amber-500 disabled:bg-gray-800 text-white text-xs font-semibold flex items-center justify-center space-x-1.5 transition-all"
          >
            <Plus size={16} />
            <span>Enlist Target</span>
          </button>
        </form>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 font-mono">
        {/* Watchlist Table */}
        <div className="p-5 rounded-xl bg-[#0e1422] border border-gray-800 space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-xs font-bold text-gray-200 uppercase flex items-center space-x-2">
              <Bell size={16} className="text-amber-400" />
              <span>Monitored Watchlist ({watchlist.length})</span>
            </h3>
            <button onClick={loadData} className="text-gray-400 hover:text-white">
              <RefreshCw size={14} />
            </button>
          </div>

          {watchlist.length > 0 ? (
            <div className="space-y-2">
              {watchlist.map((w) => (
                <div key={w.id} className="p-3 rounded-lg bg-gray-900 border border-gray-800 flex justify-between items-center text-xs">
                  <div>
                    <div className="font-bold text-gray-200">{w.target}</div>
                    <div className="text-[10px] text-gray-500 mt-0.5">
                      Type: {w.type} &bull; Added: {new Date(w.addedAt).toLocaleDateString()}
                    </div>
                  </div>
                  <button
                    onClick={() => handleRemove(w.id)}
                    className="p-1.5 text-gray-500 hover:text-red-400 transition-colors"
                  >
                    <Trash2 size={16} />
                  </button>
                </div>
              ))}
            </div>
          ) : (
            <div className="py-8 text-center text-xs text-gray-500">
              No targets currently on watchlist. Enlist a target above to begin polling.
            </div>
          )}
        </div>

        {/* Monitoring Jobs */}
        <div className="p-5 rounded-xl bg-[#0e1422] border border-gray-800 space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-xs font-bold text-gray-200 uppercase flex items-center space-x-2">
              <Activity size={16} className="text-blue-400" />
              <span>Automated Telemetry Jobs ({jobs.length})</span>
            </h3>
          </div>

          {jobs.length > 0 ? (
            <div className="space-y-2">
              {jobs.map((j) => (
                <div key={j.id} className="p-3 rounded-lg bg-gray-900 border border-gray-800 flex justify-between items-center text-xs">
                  <div>
                    <div className="font-bold text-gray-200">{j.target}</div>
                    <div className="text-[10px] text-gray-500 mt-0.5">
                      Interval: {j.intervalMinutes}m &bull; Last: {j.lastRun ? new Date(j.lastRun).toLocaleTimeString() : 'Pending'}
                    </div>
                  </div>
                  <button
                    onClick={() => handleTriggerJob(j.id)}
                    className="px-2.5 py-1 rounded bg-blue-950 text-blue-400 border border-blue-800 hover:bg-blue-900 text-[11px]"
                  >
                    Run Poll Now
                  </button>
                </div>
              ))}
            </div>
          ) : (
            <div className="py-8 text-center text-xs text-gray-500">
              Zero continuous monitoring jobs initialized.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
