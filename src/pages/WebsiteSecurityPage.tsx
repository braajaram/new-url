import React, { useState } from 'react';
import { Terminal, Search, ShieldCheck, AlertTriangle, CheckCircle, XCircle } from 'lucide-react';
import { SecurityHeadersAnalysis } from '../types/threat';

export const WebsiteSecurityPage: React.FC = () => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<SecurityHeadersAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleAnalyze = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setError(null);
    setData(null);

    try {
      const res = await fetch('/api/website/security', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url.trim() })
      });
      if (!res.ok) throw new Error('Header analysis failed');
      const json = await res.json();
      setData(json.securityHeaders);
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
          <h1 className="text-xl font-bold text-white tracking-wide">Website Security & Defense Headers</h1>
          <span className="px-2 py-0.5 text-[10px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-800 rounded">
            HAR-AUDIT
          </span>
        </div>
        <p className="text-xs text-gray-400 mt-1">
          Inspects HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and Referrer policy configurations.
        </p>
      </div>

      <div className="p-5 rounded-xl bg-[#0e1422] border border-gray-800">
        <form onSubmit={handleAnalyze} className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="URL (e.g. https://example.com)..."
            className="flex-1 bg-[#131b2c] border border-gray-700 text-sm text-gray-100 placeholder-gray-500 px-4 py-3 rounded-lg focus:outline-none focus:border-emerald-500 font-mono"
          />
          <button
            type="submit"
            disabled={loading || !url.trim()}
            className="px-6 py-3 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:bg-gray-800 text-white text-sm font-semibold flex items-center justify-center space-x-2 transition-all"
          >
            <Terminal size={16} />
            <span>{loading ? 'Inspecting Headers...' : 'Inspect Security Headers'}</span>
          </button>
        </form>

        {error && <div className="mt-4 text-xs font-mono text-red-400">Error: {error}</div>}
      </div>

      {data && (
        <div className="space-y-6 font-mono">
          <div className="p-5 rounded-xl bg-[#0e1422] border border-gray-800 flex justify-between items-center">
            <div>
              <div className="text-xs text-gray-400 uppercase">Defense Hardening Score</div>
              <div className="text-3xl font-extrabold text-emerald-400 mt-1">{data.score}/100</div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-5 rounded-xl bg-[#0e1422] border border-gray-800 space-y-3">
              <h3 className="text-xs font-bold text-gray-200 uppercase">Active Defense Headers ({data.present.length})</h3>
              <div className="space-y-2 text-xs">
                {data.present.map((h, i) => (
                  <div key={i} className="p-2.5 rounded bg-gray-900 border border-gray-800 flex justify-between">
                    <span className="text-emerald-400 font-bold">{h.header}</span>
                    <span className="text-gray-300 truncate max-w-xs">{h.value}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="p-5 rounded-xl bg-[#0e1422] border border-gray-800 space-y-3">
              <h3 className="text-xs font-bold text-gray-200 uppercase">Missing Protective Policies ({data.missing.length})</h3>
              <div className="space-y-2 text-xs">
                {data.missing.map((m, i) => (
                  <div key={i} className="p-2.5 rounded bg-gray-900 border border-red-900/40">
                    <div className="flex justify-between">
                      <span className="text-red-400 font-bold">{m.header}</span>
                      <span className="text-[10px] text-gray-500 uppercase">{m.severity} RISK</span>
                    </div>
                    <div className="text-[11px] text-gray-400 mt-1">{m.recommendation}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {!data && !loading && (
        <div className="p-12 text-center rounded-xl bg-[#0e1422]/60 border border-gray-800">
          <Terminal size={40} className="mx-auto mb-3 opacity-30 text-gray-400" />
          <h3 className="text-sm font-semibold text-gray-300">Ready for HTTP Header Scan</h3>
          <p className="text-xs text-gray-500 mt-1 max-w-sm mx-auto">
            Audit HTTP response headers to identify missing clickjacking and content sniffing defenses.
          </p>
        </div>
      )}
    </div>
  );
};
