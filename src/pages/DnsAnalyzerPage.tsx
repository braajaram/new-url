import React, { useState } from 'react';
import { Network, Search, AlertCircle, CheckCircle } from 'lucide-react';

export const DnsAnalyzerPage: React.FC = () => {
  const [domain, setDomain] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const handleLookup = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!domain.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const clean = domain.trim().replace(/^https?:\/\//, '').split('/')[0];
      const res = await fetch(`/api/dns/${encodeURIComponent(clean)}`);
      if (!res.ok) throw new Error('DNS Query failure');
      const data = await res.json();
      setResult(data);
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
          <h1 className="text-xl font-bold text-white tracking-wide">Live DNS Record Inspector</h1>
          <span className="px-2 py-0.5 text-[10px] font-mono bg-cyan-950 text-cyan-400 border border-cyan-800 rounded">
            NATIVE RESOLVER
          </span>
        </div>
        <p className="text-xs text-gray-400 mt-1">
          Queries authoritative nameservers for A, AAAA, MX, NS, and TXT records with TTL analysis.
        </p>
      </div>

      <div className="p-5 rounded-xl bg-[#0e1422] border border-gray-800">
        <form onSubmit={handleLookup} className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="Domain name (e.g. github.com)..."
            className="flex-1 bg-[#131b2c] border border-gray-700 text-sm text-gray-100 placeholder-gray-500 px-4 py-3 rounded-lg focus:outline-none focus:border-cyan-500 font-mono"
          />
          <button
            type="submit"
            disabled={loading || !domain.trim()}
            className="px-6 py-3 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:bg-gray-800 text-white text-sm font-semibold flex items-center justify-center space-x-2 transition-all"
          >
            <Search size={16} />
            <span>{loading ? 'Resolving...' : 'Lookup DNS Records'}</span>
          </button>
        </form>

        {error && <div className="mt-4 text-xs font-mono text-red-400">DNS Error: {error}</div>}
      </div>

      {result && (
        <div className="space-y-4 font-mono">
          <div className="p-4 rounded-xl bg-[#0e1422] border border-gray-800">
            <h3 className="text-xs font-bold text-gray-200 uppercase mb-3">Extracted DNS Records</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-gray-800 text-gray-400">
                    <th className="pb-2">TYPE</th>
                    <th className="pb-2">VALUE / TARGET</th>
                    <th className="pb-2">TTL</th>
                    <th className="pb-2">STATUS</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800">
                  {result.records?.map((r: any, i: number) => (
                    <tr key={i} className="hover:bg-gray-900/50">
                      <td className="py-2.5 font-bold text-cyan-400">{r.type}</td>
                      <td className="py-2.5 text-gray-200">{r.value}</td>
                      <td className="py-2.5 text-gray-400">{r.ttl ? `${r.ttl}s` : 'DYNAMIC'}</td>
                      <td className="py-2.5">
                        <span className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-950 text-emerald-400">
                          {r.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {!result && !loading && (
        <div className="p-12 text-center rounded-xl bg-[#0e1422]/60 border border-gray-800">
          <Network size={40} className="mx-auto mb-3 opacity-30 text-gray-400" />
          <h3 className="text-sm font-semibold text-gray-300">No Query Executed</h3>
          <p className="text-xs text-gray-500 mt-1 max-w-sm mx-auto">
            Input a domain to query global authoritative DNS trees in real time.
          </p>
        </div>
      )}
    </div>
  );
};
