import React, { useState } from 'react';
import { Key, Search, Lock, AlertTriangle, CheckCircle, XCircle } from 'lucide-react';
import { TlsAnalysisResult } from '../types/threat';

export const TlsAnalyzerPage: React.FC = () => {
  const [domain, setDomain] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<TlsAnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleInspect = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!domain.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const clean = domain.trim().replace(/^https?:\/\//, '').split('/')[0];
      const res = await fetch(`/api/tls/${encodeURIComponent(clean)}`);
      if (!res.ok) throw new Error('TLS Handshake failed');
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
          <h1 className="text-xl font-bold text-white tracking-wide">TLS / SSL Handshake & Certificate Auditor</h1>
          <span className="px-2 py-0.5 text-[10px] font-mono bg-amber-950 text-amber-400 border border-amber-800 rounded">
            CRYPTOGRAPHY AUDIT
          </span>
        </div>
        <p className="text-xs text-gray-400 mt-1">
          Conducts an active native TLS socket handshake on port 443, auditing expiry, authority, and SAN coverage.
        </p>
      </div>

      <div className="p-5 rounded-xl bg-[#0e1422] border border-gray-800">
        <form onSubmit={handleInspect} className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="Target Hostname (e.g. google.com or expired.badssl.com)..."
            className="flex-1 bg-[#131b2c] border border-gray-700 text-sm text-gray-100 placeholder-gray-500 px-4 py-3 rounded-lg focus:outline-none focus:border-amber-500 font-mono"
          />
          <button
            type="submit"
            disabled={loading || !domain.trim()}
            className="px-6 py-3 rounded-lg bg-amber-600 hover:bg-amber-500 disabled:bg-gray-800 text-white text-sm font-semibold flex items-center justify-center space-x-2 transition-all"
          >
            <Key size={16} />
            <span>{loading ? 'Auditing Handshake...' : 'Audit TLS Certificate'}</span>
          </button>
        </form>

        {error && <div className="mt-4 text-xs font-mono text-red-400">Error: {error}</div>}
      </div>

      {result && (
        <div className="space-y-6 font-mono">
          <div className="p-5 rounded-xl bg-[#0e1422] border border-gray-800 flex justify-between items-center">
            <div>
              <div className="text-xs text-gray-400 uppercase">Certificate State</div>
              <div className="text-lg font-bold text-white mt-1">
                {result.valid ? 'Cryptographically Trusted & Valid' : 'Invalid / Untrusted / Expired'}
              </div>
            </div>
            <span className={`px-3 py-1 rounded text-xs font-bold ${
              result.valid ? 'bg-emerald-950 text-emerald-400' : 'bg-red-950 text-red-400'
            }`}>
              {result.timelineStatus}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-5 rounded-xl bg-[#0e1422] border border-gray-800 space-y-3">
              <h3 className="text-xs font-bold text-gray-200 uppercase">Certificate Timeline</h3>
              <div className="space-y-2 text-xs">
                <div className="flex justify-between border-b border-gray-800/80 pb-1.5">
                  <span className="text-gray-400">Days Remaining:</span>
                  <span className="text-gray-200 font-bold">{result.daysRemaining ?? 'N/A'}</span>
                </div>
                <div className="flex justify-between border-b border-gray-800/80 pb-1.5">
                  <span className="text-gray-400">Valid From:</span>
                  <span className="text-gray-200">{result.validFrom || 'N/A'}</span>
                </div>
                <div className="flex justify-between border-b border-gray-800/80 pb-1.5">
                  <span className="text-gray-400">Valid To:</span>
                  <span className="text-gray-200">{result.validTo || 'N/A'}</span>
                </div>
              </div>
            </div>

            <div className="p-5 rounded-xl bg-[#0e1422] border border-gray-800 space-y-3">
              <h3 className="text-xs font-bold text-gray-200 uppercase">Issuer & SAN Metadata</h3>
              <div className="space-y-2 text-xs">
                <div className="flex justify-between border-b border-gray-800/80 pb-1.5">
                  <span className="text-gray-400">Common Name (CN):</span>
                  <span className="text-gray-200">{result.subject?.CN || 'N/A'}</span>
                </div>
                <div className="flex justify-between border-b border-gray-800/80 pb-1.5">
                  <span className="text-gray-400">Issuer CA:</span>
                  <span className="text-gray-200">{result.issuer?.O || result.issuer?.CN || 'N/A'}</span>
                </div>
                <div className="flex justify-between border-b border-gray-800/80 pb-1.5">
                  <span className="text-gray-400">Hostname Match:</span>
                  <span className={result.hostnameMatch ? 'text-emerald-400' : 'text-red-400'}>
                    {result.hostnameMatch ? 'VERIFIED' : 'FAILED'}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {!result && !loading && (
        <div className="p-12 text-center rounded-xl bg-[#0e1422]/60 border border-gray-800">
          <Key size={40} className="mx-auto mb-3 opacity-30 text-gray-400" />
          <h3 className="text-sm font-semibold text-gray-300">Awaiting TLS Target</h3>
          <p className="text-xs text-gray-500 mt-1 max-w-sm mx-auto">
            Test any HTTPS domain to discover cipher attributes, validity dates, and trust chains.
          </p>
        </div>
      )}
    </div>
  );
};
