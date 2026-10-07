import React, { useState } from 'react';
import { 
  ShieldAlert, ShieldCheck, AlertTriangle, ArrowRight, 
  Terminal, Globe, Network, Lock, Cpu, Eye, CheckCircle2, XCircle, ChevronDown, ChevronUp, Copy, Check
} from 'lucide-react';
import { ScanResult } from '../types/threat';

interface UrlAnalyzerProps {
  initialTarget?: string;
  onScanComplete?: (scan: ScanResult) => void;
}

export const UrlAnalyzerPage: React.FC<UrlAnalyzerProps> = ({ initialTarget = '', onScanComplete }) => {
  const [target, setTarget] = useState(initialTarget);
  const [loading, setLoading] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Scan pipeline stage indicator
  const [currentStage, setCurrentStage] = useState<string>('');

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!target.trim()) return;

    setLoading(true);
    setError(null);
    setScanResult(null);

    try {
      setCurrentStage('Initializing SSRF Filter & Normalizer...');
      await new Promise(r => setTimeout(r, 200));

      setCurrentStage('Performing Outbound DNS & Network Resolution...');
      await new Promise(r => setTimeout(r, 200));

      setCurrentStage('Executing TLS Handshake & Header Audit...');
      await new Promise(r => setTimeout(r, 200));

      setCurrentStage('Running Scikit-Learn ML Feature Extractor...');

      const res = await fetch('/api/url/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target.trim() })
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error || 'Security analysis execution failed');
      }

      const data: ScanResult = await res.json();
      setScanResult(data);
      if (onScanComplete) onScanComplete(data);
    } catch (err: any) {
      setError(err.message || 'Scan failed');
    } finally {
      setLoading(false);
      setCurrentStage('');
    }
  };

  const copyIoc = () => {
    if (!scanResult) return;
    navigator.clipboard.writeText(JSON.stringify(scanResult, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center space-x-2">
          <h1 className="text-xl font-bold text-white tracking-wide">Multi-Vector URL & Threat Engine</h1>
          <span className="px-2 py-0.5 text-[10px] font-mono bg-red-950 text-red-400 border border-red-800 rounded">
            LIVE ENGINE
          </span>
        </div>
        <p className="text-xs text-gray-400 mt-1">
          Performs lexical neural classification, real DNS resolution, native TLS inspection, and SSRF validation.
        </p>
      </div>

      {/* Target Input Form */}
      <div className="p-5 rounded-xl bg-[#0e1422] border border-gray-800 shadow-xl">
        <form onSubmit={handleScan} className="flex flex-col sm:flex-row gap-3">
          <div className="flex-1 relative">
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="Enter URL, Domain, or IP address (e.g. https://account-verification-login.top)..."
              disabled={loading}
              className="w-full bg-[#131b2c] border border-gray-700 text-sm text-gray-100 placeholder-gray-500 px-4 py-3 rounded-lg focus:outline-none focus:border-red-500 font-mono disabled:opacity-50"
            />
          </div>
          <button
            type="submit"
            disabled={loading || !target.trim()}
            className="px-6 py-3 rounded-lg bg-red-600 hover:bg-red-500 disabled:bg-gray-800 text-white text-sm font-semibold flex items-center justify-center space-x-2 transition-all shadow-md shadow-red-950 disabled:text-gray-500"
          >
            <ShieldAlert size={16} />
            <span>{loading ? 'Analyzing...' : 'Execute Deep Inspection'}</span>
          </button>
        </form>

        {/* Live Loading Stage */}
        {loading && (
          <div className="mt-4 p-3 rounded-lg bg-gray-900 border border-gray-800 flex items-center space-x-3 text-xs font-mono text-gray-300">
            <div className="w-3.5 h-3.5 border-2 border-red-500 border-t-transparent rounded-full animate-spin" />
            <span>{currentStage}</span>
          </div>
        )}

        {/* Error Notification */}
        {error && (
          <div className="mt-4 p-3 rounded-lg bg-red-950/40 border border-red-800/80 text-xs font-mono text-red-300 flex items-center space-x-2">
            <XCircle size={16} className="text-red-400 shrink-0" />
            <span>Scan Error: {error}</span>
          </div>
        )}
      </div>

      {/* Results View */}
      {scanResult && (
        <div className="space-y-6">
          {/* Main Verdict Card */}
          <div className={`p-6 rounded-xl border ${
            scanResult.overallRisk === 'MALICIOUS'
              ? 'bg-[#180d11] border-red-800/80 shadow-2xl shadow-red-950/30'
              : scanResult.overallRisk === 'SUSPICIOUS'
              ? 'bg-[#18130d] border-amber-800/80 shadow-2xl shadow-amber-950/30'
              : 'bg-[#0d1813] border-emerald-800/80 shadow-2xl shadow-emerald-950/30'
          }`}>
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center space-x-3">
                  <span className={`px-3 py-1 rounded text-xs font-mono font-bold tracking-widest ${
                    scanResult.overallRisk === 'MALICIOUS'
                      ? 'bg-red-950 text-red-400 border border-red-700'
                      : scanResult.overallRisk === 'SUSPICIOUS'
                      ? 'bg-amber-950 text-amber-400 border border-amber-700'
                      : 'bg-emerald-950 text-emerald-400 border border-emerald-700'
                  }`}>
                    VERDICT: {scanResult.overallRisk}
                  </span>
                  <span className="text-xs font-mono text-gray-400">
                    Confidence: {scanResult.confidence}%
                  </span>
                  <span className="text-xs font-mono text-gray-400">
                    Execution: {scanResult.executionTimeMs}ms
                  </span>
                </div>
                <div className="text-base font-bold text-white font-mono break-all pt-1">
                  {scanResult.target}
                </div>
              </div>

              <div className="flex items-center space-x-4">
                <div className="text-right">
                  <div className="text-[10px] font-mono text-gray-400 uppercase">Risk Metric</div>
                  <div className={`text-3xl font-extrabold font-mono ${
                    scanResult.overallRisk === 'MALICIOUS' ? 'text-red-500' : (scanResult.overallRisk === 'SUSPICIOUS' ? 'text-amber-500' : 'text-emerald-500')
                  }`}>
                    {scanResult.riskScore}<span className="text-sm font-normal text-gray-500">/100</span>
                  </div>
                </div>

                <button
                  onClick={copyIoc}
                  className="p-2 rounded-lg bg-gray-900 border border-gray-800 hover:border-gray-700 text-gray-300 transition-colors"
                  title="Copy Full IOC JSON"
                >
                  {copied ? <Check size={16} className="text-emerald-400" /> : <Copy size={16} />}
                </button>
              </div>
            </div>

            {/* Reasons Identified */}
            <div className="mt-5 pt-4 border-t border-gray-800/80">
              <div className="text-xs font-mono uppercase tracking-wider text-gray-400 mb-2 font-bold">
                Identified Risk Factors & Detections:
              </div>
              <ul className="space-y-1 text-xs font-mono text-gray-200">
                {scanResult.reasons.map((r, i) => (
                  <li key={i} className="flex items-start space-x-2">
                    <span className="text-red-400 mt-0.5">&bull;</span>
                    <span>{r}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Detailed Telemetry Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {/* DNS Intelligence */}
            <div className="p-5 rounded-xl bg-[#0e1422] border border-gray-800 space-y-3">
              <div className="flex items-center justify-between text-xs font-mono font-bold text-gray-200">
                <div className="flex items-center space-x-2">
                  <Network size={16} className="text-blue-400" />
                  <span>DNS RESOLUTION</span>
                </div>
                <span className="text-emerald-400">{scanResult.dns?.status || 'NO_DATA'}</span>
              </div>

              <div className="space-y-1.5 text-xs font-mono">
                {scanResult.dns?.records && scanResult.dns.records.length > 0 ? (
                  scanResult.dns.records.map((rec, i) => (
                    <div key={i} className="p-2 rounded bg-gray-900/60 border border-gray-800/60 flex justify-between">
                      <span className="text-gray-400">{rec.type}</span>
                      <span className="text-gray-200 truncate max-w-[180px]">{rec.value}</span>
                    </div>
                  ))
                ) : (
                  <div className="text-gray-500 py-4 text-center">No active DNS records found</div>
                )}
              </div>
            </div>

            {/* TLS Certificate Audit */}
            <div className="p-5 rounded-xl bg-[#0e1422] border border-gray-800 space-y-3">
              <div className="flex items-center justify-between text-xs font-mono font-bold text-gray-200">
                <div className="flex items-center space-x-2">
                  <Lock size={16} className="text-amber-400" />
                  <span>TLS / SSL CERTIFICATE</span>
                </div>
                <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                  scanResult.tls?.valid ? 'bg-emerald-950 text-emerald-400' : 'bg-red-950 text-red-400'
                }`}>
                  {scanResult.tls?.timelineStatus || 'NO_TLS'}
                </span>
              </div>

              {scanResult.tls ? (
                <div className="space-y-2 text-xs font-mono">
                  <div className="flex justify-between border-b border-gray-800/60 pb-1">
                    <span className="text-gray-400">Days Remaining:</span>
                    <span className="text-gray-200">{scanResult.tls.daysRemaining ?? 'N/A'}</span>
                  </div>
                  <div className="flex justify-between border-b border-gray-800/60 pb-1">
                    <span className="text-gray-400">Protocol:</span>
                    <span className="text-gray-200">{scanResult.tls.protocol || 'TLS'}</span>
                  </div>
                  <div className="flex justify-between border-b border-gray-800/60 pb-1">
                    <span className="text-gray-400">Host Match:</span>
                    <span className={scanResult.tls.hostnameMatch ? 'text-emerald-400' : 'text-red-400'}>
                      {scanResult.tls.hostnameMatch ? 'MATCHED' : 'MISMATCH'}
                    </span>
                  </div>
                  {scanResult.tls.issuer && (
                    <div className="pt-1 text-[11px] text-gray-400 truncate">
                      Issuer: {scanResult.tls.issuer.O || scanResult.tls.issuer.CN || 'Unknown CA'}
                    </div>
                  )}
                </div>
              ) : (
                <div className="text-gray-500 py-4 text-center">Target does not negotiate TLS</div>
              )}
            </div>

            {/* AI / ML Lexical Features */}
            <div className="p-5 rounded-xl bg-[#0e1422] border border-gray-800 space-y-3">
              <div className="flex items-center justify-between text-xs font-mono font-bold text-gray-200">
                <div className="flex items-center space-x-2">
                  <Cpu size={16} className="text-red-400" />
                  <span>AI ML CLASSIFIER</span>
                </div>
                <span className="text-gray-400">{scanResult.mlResult?.modelVersion}</span>
              </div>

              {scanResult.mlResult ? (
                <div className="space-y-2 text-xs font-mono">
                  <div className="flex justify-between border-b border-gray-800/60 pb-1">
                    <span className="text-gray-400">Shannon Entropy:</span>
                    <span className="text-gray-200">{scanResult.mlResult.lexicalFeatures.entropy}</span>
                  </div>
                  <div className="flex justify-between border-b border-gray-800/60 pb-1">
                    <span className="text-gray-400">Punycode Flag:</span>
                    <span className={scanResult.mlResult.lexicalFeatures.hasPunycode ? 'text-red-400 font-bold' : 'text-gray-400'}>
                      {scanResult.mlResult.lexicalFeatures.hasPunycode ? 'TRUE' : 'FALSE'}
                    </span>
                  </div>
                  <div className="flex justify-between border-b border-gray-800/60 pb-1">
                    <span className="text-gray-400">Keyword Hooks:</span>
                    <span className="text-gray-200">{scanResult.mlResult.lexicalFeatures.suspiciousKeywordsCount}</span>
                  </div>
                  <div className="flex justify-between border-b border-gray-800/60 pb-1">
                    <span className="text-gray-400">At-Symbol Trick:</span>
                    <span className={scanResult.mlResult.lexicalFeatures.hasAtSymbol ? 'text-red-400 font-bold' : 'text-gray-400'}>
                      {scanResult.mlResult.lexicalFeatures.hasAtSymbol ? 'DETECTED' : 'NONE'}
                    </span>
                  </div>
                </div>
              ) : (
                <div className="text-gray-500 py-4 text-center">ML Model Not Evaluated</div>
              )}
            </div>
          </div>

          {/* Redirect Chain Visualization */}
          {scanResult.redirectChain && scanResult.redirectChain.chain.length > 0 && (
            <div className="p-5 rounded-xl bg-[#0e1422] border border-gray-800 space-y-3">
              <div className="flex items-center justify-between text-xs font-mono font-bold text-gray-200">
                <div className="flex items-center space-x-2">
                  <Terminal size={16} className="text-indigo-400" />
                  <span>REDIRECT CHAIN INSPECTION ({scanResult.redirectChain.count} HOPS)</span>
                </div>
                {scanResult.redirectChain.isSuspicious && (
                  <span className="text-red-400 font-mono text-xs">SUSPICIOUS CHAIN</span>
                )}
              </div>

              <div className="space-y-2">
                {scanResult.redirectChain.chain.map((step: any, i: number) => (
                  <div key={i} className="p-3 rounded-lg bg-gray-900/80 border border-gray-800 flex items-center justify-between text-xs font-mono">
                    <div className="flex items-center space-x-3">
                      <span className="px-2 py-0.5 rounded bg-gray-800 text-gray-300 font-bold">
                        HOP {step.step}
                      </span>
                      <span className="text-gray-400">{step.status}</span>
                      <span className="text-gray-200 truncate max-w-md">{step.url}</span>
                    </div>
                    <div className="text-gray-500 text-[11px]">
                      {step.durationMs}ms
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Empty State */}
      {!scanResult && !loading && (
        <div className="p-12 text-center rounded-xl bg-[#0e1422]/60 border border-gray-800">
          <ShieldCheck size={40} className="mx-auto mb-3 opacity-30 text-gray-400" />
          <h3 className="text-sm font-semibold text-gray-300">Ready for Indicator Submission</h3>
          <p className="text-xs text-gray-500 mt-1 max-w-md mx-auto">
            Input a URL, registered domain, or external IP address to inspect its DNS records, TLS health, redirect trail, and ML threat profile.
          </p>
        </div>
      )}
    </div>
  );
};
