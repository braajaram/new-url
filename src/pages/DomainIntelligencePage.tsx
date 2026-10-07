import React, { useState } from 'react';
import { Globe, Search, Network, Lock, ShieldAlert, CheckCircle, AlertTriangle, ArrowRight } from 'lucide-react';

export const DomainIntelligencePage: React.FC<{ initialDomain?: string }> = ({ initialDomain = '' }) => {
  const [domain, setDomain] = useState(initialDomain);
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSearch = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!domain.trim()) return;

    setLoading(true);
    setError(null);
    setData(null);

    try {
      const clean = domain.trim().replace(/^https?:\/\//, '').split('/')[0];
      const res = await fetch(`/api/domains/${encodeURIComponent(clean)}`);
      if (!res.ok) {
        const d = await res.json();
        throw new Error(d.error || 'Domain lookup failed');
      }
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
          <h1 className="text-xl font-bold text-white tracking-wide">Domain Intelligence & Nameserver Recon</h1>
          <span className="px-2 py-0.5 text-[10px] font-mono bg-blue-950 text-blue-400 border border-blue-800 rounded">
            RECON REPOSITORY
          </span>
        </div>
        <p className="text-xs text-gray-400 mt-1">
          Perform live DNS zone extraction, nameserver profiling, and certificate discovery for any root domain.
        </p>
      </div>

      <div className="p-5 rounded-xl bg-[#0e1422] border border-gray-800 shadow-xl">
        <form onSubmit={handleSearch} className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="Enter domain (e.g. cloudflare.com or paypal-security.xyz)..."
            className="flex-1 bg-[#131b2c] border border-gray-700 text-sm text-gray-100 placeholder-gray-500 px-4 py-3 rounded-lg focus:outline-none focus:border-blue-500 font-mono"
          />
          <button
            type="submit"
            disabled={loading || !domain.trim()}
            className="px-6 py-3 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:bg-gray-800 text-white text-sm font-semibold flex items-center justify-center space-x-2 transition-all shadow-md"
          >
            <Search size={16} />
            <span>{loading ? 'Interrogating...' : 'Investigate Domain'}</span>
          </button>
        </form>

        {error && (
          <div className="mt-4 p-3 rounded-lg bg-red-950/40 border border-red-800 text-xs font-mono text-red-300">
            Error: {error}
          </div>
        )}
      </div>

      {data && (
        <div className="space-y-6 font-mono">
          <div className="p-5 rounded-xl bg-[#0e1422] border border-gray-800 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
            <div>
              <div className="text-xs text-gray-400 uppercase">Target Domain</div>
              <div className="text-lg font-bold text-white mt-1">{data.domain}</div>
              <div className="text-xs text-gray-500 mt-0.5">Top-Level Domain: .{data.tld}</div>
            </div>
            <div className="flex items-center space-x-3">
              <span className={`px-3 py-1 rounded text-xs font-bold ${
                data.reputation === 'MALICIOUS'
                  ? 'bg-red-950 text-red-400 border border-red-800'
                  : data.reputation === 'SAFE'
                  ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                  : 'bg-gray-800 text-gray-300'
              }`}>
                REPUTATION: {data.reputation}
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* DNS Records */}
            <div className="p-5 rounded-xl bg-[#0e1422] border border-gray-800 space-y-3">
              <h3 className="text-xs font-bold text-gray-200 uppercase flex items-center space-x-2">
                <Network size={16} className="text-blue-400" />
                <span>DNS Zone Records ({data.dns?.records?.length || 0})</span>
              </h3>
              <div className="space-y-2 text-xs">
                {data.dns?.records?.map((rec: any, idx: number) => (
                  <div key={idx} className="p-2.5 rounded bg-gray-900 border border-gray-800 flex justify-between">
                    <span className="text-blue-400 font-bold">{rec.type}</span>
                    <span className="text-gray-200 max-w-xs truncate">{rec.value}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Nameservers & Authority */}
            <div className="p-5 rounded-xl bg-[#0e1422] border border-gray-800 space-y-3">
              <h3 className="text-xs font-bold text-gray-200 uppercase flex items-center space-x-2">
                <Globe size={16} className="text-purple-400" />
                <span>Authoritative Nameservers</span>
              </h3>
              <div className="space-y-2 text-xs">
                {data.dns?.nameservers && data.dns.nameservers.length > 0 ? (
                  data.dns.nameservers.map((ns: string, idx: number) => (
                    <div key={idx} className="p-2.5 rounded bg-gray-900 border border-gray-800 text-gray-200">
                      {ns}
                    </div>
                  ))
                ) : (
                  <div className="text-gray-500 py-4 text-center">No authoritative NS retrieved</div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {!data && !loading && (
        <div className="p-12 text-center rounded-xl bg-[#0e1422]/60 border border-gray-800">
          <Globe size={40} className="mx-auto mb-3 opacity-30 text-gray-400" />
          <h3 className="text-sm font-semibold text-gray-300">Awaiting Domain Inquiry</h3>
          <p className="text-xs text-gray-500 mt-1 max-w-sm mx-auto">
            Query any fully qualified domain name to inspect authoritative zone delegations, live MX routing, and TLS certificates.
          </p>
        </div>
      )}
    </div>
  );
};
