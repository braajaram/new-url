import React, { useState } from 'react';
import { QrCode, Upload, ArrowRight, ShieldAlert, CheckCircle } from 'lucide-react';
import { ScanResult } from '../types/threat';

export const QrScannerPage: React.FC<{ onInspectUrl: (target: string) => void }> = ({ onInspectUrl }) => {
  const [loading, setLoading] = useState(false);
  const [decodedUrl, setDecodedUrl] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);

  const handleTestSample = async (sampleUrl: string) => {
    setLoading(true);
    setDecodedUrl(sampleUrl);

    try {
      const res = await fetch('/api/qr/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ imageBase64: 'qr_sample:' + sampleUrl })
      });
      const data = await res.json();
      setScanResult(data.scanResult);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      <div>
        <div className="flex items-center space-x-2">
          <h1 className="text-xl font-bold text-white tracking-wide">QR Threat & Quishing Analyzer</h1>
          <span className="px-2 py-0.5 text-[10px] font-mono bg-red-950 text-red-400 border border-red-800 rounded">
            ANTI-QUISHING
          </span>
        </div>
        <p className="text-xs text-gray-400 mt-1">
          Extract URLs embedded within QR codes and run them through our multi-vector threat engine before scanning on mobile devices.
        </p>
      </div>

      <div className="p-8 rounded-xl bg-[#0e1422] border border-gray-800 text-center">
        <QrCode size={48} className="mx-auto text-red-400 mb-3" />
        <h3 className="text-base font-semibold text-white">Analyze Suspicious QR Codes</h3>
        <p className="text-xs text-gray-400 mt-1 max-w-md mx-auto">
          Test simulated malicious quishing payloads to observe how the AI scanner intercepts brand impersonation.
        </p>

        <div className="mt-6 flex flex-wrap justify-center gap-3">
          <button
            onClick={() => handleTestSample('https://paypal-update-account.security-alert.top/verify')}
            disabled={loading}
            className="px-4 py-2 rounded-lg bg-red-950/60 border border-red-800/80 hover:bg-red-900/60 text-xs font-mono text-red-300"
          >
            Scan Phishing QR Sample (Paypal Lookalike)
          </button>
          <button
            onClick={() => handleTestSample('https://google.com')}
            disabled={loading}
            className="px-4 py-2 rounded-lg bg-emerald-950/60 border border-emerald-800/80 hover:bg-emerald-900/60 text-xs font-mono text-emerald-300"
          >
            Scan Clean QR Sample (Google)
          </button>
        </div>
      </div>

      {loading && (
        <div className="p-6 text-center font-mono text-xs text-gray-400">
          Decoding QR barcode matrix and analyzing destination payload...
        </div>
      )}

      {scanResult && (
        <div className="p-6 rounded-xl bg-[#0e1422] border border-gray-800 space-y-4 font-mono">
          <div className="flex justify-between items-center">
            <div>
              <div className="text-xs text-gray-400">DECODED QR URL</div>
              <div className="text-base font-bold text-white break-all mt-1">{decodedUrl}</div>
            </div>
            <span className={`px-3 py-1 rounded text-xs font-bold ${
              scanResult.overallRisk === 'MALICIOUS' ? 'bg-red-950 text-red-400' : 'bg-emerald-950 text-emerald-400'
            }`}>
              {scanResult.overallRisk}
            </span>
          </div>

          <div className="pt-4 border-t border-gray-800">
            <button
              onClick={() => onInspectUrl(scanResult.target)}
              className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white rounded text-xs font-semibold flex items-center space-x-2"
            >
              <span>View Full SOC Telemetry Report</span>
              <ArrowRight size={14} />
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
