import React, { useState } from 'react';
import { Server, Search, ShieldCheck, AlertTriangle } from 'lucide-react';

export const IpIntelligencePage: React.FC = () => {
  const [ip, setIp] = useState('');
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const handleLookup = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!ip.trim()) return;

    setLoading(true);
    setError(null);
    setData(null);

    try {
      const res = await fetch(`/api/ip/${encodeURIComponent(ip.trim())}`);
      if (!res.ok) throw new Error('IP Intelligence query failed');
      const json = await res.json();
      setData(json);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      <div>
        <div className="flex items-center space-x-2">
          <h1 className="text-xl font-bold text-white tracking-wide">IP Address Telemetry & Threat Reputation</h1>
          <span className="px-2 py-0.5 text-[10px] font-mono bg-purple-950 text-purple-400 border border-purple-800 rounded">
            ROUTING ANALYZER
          </span>
        </div>
        <p className="text-xs text-gray-400 mt-1">
          Inspect IPv4/IPv6 indicators, private address reservations, and localized abuse history.
        </p>
      </div>

      <div className="p-5 rounded-xl bg-[#0e1422] border border-gray-800">
        <form onSubmit={handleLookup} className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            placeholder="IP Address (e.g. 1.1.1.1 or 8.8.8.8)..."
            className="flex-1 bg-[#131b2c] border border-gray-700 text-sm text-gray-100 placeholder-gray-500 px-4 py-3 rounded-lg focus:outline-none focus:border-purple-500 font-mono"
          />
          <button
            type="submit"
            disabled={loading || !ip.trim()}
            className="px-6 py-3 rounded-lg bg-purple-600 hover:bg-purple-500 disabled:bg-gray-800 text-white text-sm font-semibold flex items-center justify-center space-x-2 transition-all"
          >
            <Search size={16} />
            <span>{loading ? 'Inspecting IP...' : 'Investigate IP'}</span>
          </button>
        </form>

        {error && <div className="mt-4 text-xs font-mono text-red-400">Error: {error}</div>}
      </div>

      {data && (
        <div className="space-y-4 font-mono">
          <div className="p-5 rounded-xl bg-[#0e1422] border border-gray-800 flex justify-between items-center">
            <div>
              <div className="text-xs text-gray-400">INVESTIGATED IP</div>
              <div className="text-xl font-bold text-white mt-1">{data.ip}</div>
              <div className="text-xs text-gray-500 mt-1">
                {data.isPrivate ? 'PRIVATE RFC1918 / INTERNAL SPACE' : 'PUBLIC GLOBAL ROUTABLE ADDRESS'}
              </div>
            </div>
            <div>
              <span className={`px-3 py-1 rounded text-xs font-bold ${
                data.isPrivate ? 'bg-amber-950 text-amber-400' : 'bg-emerald-950 text-emerald-400'
              }`}>
                {data.reputation}
              </span>
            </div>
          </div>
        </div>
      )}

      {!data && !loading && (
        <div className="p-12 text-center rounded-xl bg-[#0e1422]/60 border border-gray-800">
          <Server size={40} className="mx-auto mb-3 opacity-30 text-gray-400" />
          <h3 className="text-sm font-semibold text-gray-300">Ready for IP Investigation</h3>
          <p className="text-xs text-gray-500 mt-1 max-w-sm mx-auto">
            Input an IP address to evaluate SSRF exposure, reverse DNS assignment, and associated attacks.
          </p>
        </div>
      )}
    </div>
  );
};
