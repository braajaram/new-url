import React, { useState, useEffect } from 'react';
import { FileText, Download, ShieldAlert, ArrowRight } from 'lucide-react';
import { ScanResult } from '../types/threat';

export const ReportsPage: React.FC = () => {
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);

  useEffect(() => {
    fetch('/api/scans?limit=25')
      .then(res => res.json())
      .then(data => {
        setScans(data);
        if (data.length > 0) setSelectedScan(data[0]);
      });
  }, []);

  const downloadJson = () => {
    if (!selectedScan) return;
    const blob = new Blob([JSON.stringify(selectedScan, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threat_report_${selectedScan.id}.json`;
    a.click();
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      <div>
        <div className="flex items-center space-x-2">
          <h1 className="text-xl font-bold text-white tracking-wide">Executive Threat Intelligence Reports</h1>
          <span className="px-2 py-0.5 text-[10px] font-mono bg-indigo-950 text-indigo-400 border border-indigo-800 rounded">
            AUDIT EXPORT
          </span>
        </div>
        <p className="text-xs text-gray-400 mt-1">
          Generate forensics dossiers containing timeline breakdowns, cryptographic proofs, and remediation advisories.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 font-mono">
        {/* Scans List */}
        <div className="p-5 rounded-xl bg-[#0e1422] border border-gray-800 space-y-3">
          <h3 className="text-xs font-bold text-gray-200 uppercase">Select Target Incident</h3>
          <div className="space-y-1.5 max-h-[600px] overflow-y-auto">
            {scans.map(s => (
              <button
                key={s.id}
                onClick={() => setSelectedScan(s)}
                className={`w-full text-left p-2.5 rounded-lg text-xs border transition-colors ${
                  selectedScan?.id === s.id
                    ? 'bg-red-950/40 border-red-800 text-red-300'
                    : 'bg-gray-900 border-gray-800 text-gray-300 hover:border-gray-700'
                }`}
              >
                <div className="font-bold truncate">{s.target}</div>
                <div className="flex justify-between text-[10px] text-gray-500 mt-1">
                  <span>{s.overallRisk}</span>
                  <span>{new Date(s.createdAt).toLocaleDateString()}</span>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Report Preview */}
        <div className="lg:col-span-2 p-6 rounded-xl bg-[#0e1422] border border-gray-800 space-y-5">
          {selectedScan ? (
            <>
              <div className="flex justify-between items-start border-b border-gray-800 pb-4">
                <div>
                  <div className="text-[10px] text-gray-500 uppercase tracking-widest">INCIDENT REPORT ID: {selectedScan.id}</div>
                  <h2 className="text-lg font-bold text-white mt-1 break-all">{selectedScan.target}</h2>
                  <div className="text-xs text-gray-400 mt-0.5">Recorded: {new Date(selectedScan.createdAt).toUTCString()}</div>
                </div>
                <button
                  onClick={downloadJson}
                  className="px-3 py-1.5 rounded-lg bg-gray-900 border border-gray-700 hover:border-gray-500 text-xs text-gray-200 flex items-center space-x-1.5"
                >
                  <Download size={14} />
                  <span>Export JSON</span>
                </button>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="p-3 rounded bg-gray-900 border border-gray-800">
                  <div className="text-[10px] text-gray-400">OVERALL CLASSIFICATION</div>
                  <div className="text-sm font-bold text-white mt-1">{selectedScan.overallRisk} ({selectedScan.riskScore}/100)</div>
                </div>
                <div className="p-3 rounded bg-gray-900 border border-gray-800">
                  <div className="text-[10px] text-gray-400">DNS RESOLUTION STATE</div>
                  <div className="text-sm font-bold text-white mt-1">{selectedScan.dns?.status || 'N/A'}</div>
                </div>
              </div>

              <div>
                <h4 className="text-xs font-bold text-gray-300 uppercase mb-2">Executive Summary & Findings</h4>
                <div className="p-3 rounded bg-gray-900 border border-gray-800 text-xs text-gray-300 space-y-1">
                  {selectedScan.reasons.map((r, i) => (
                    <div key={i}>&bull; {r}</div>
                  ))}
                </div>
              </div>

              <div>
                <h4 className="text-xs font-bold text-gray-300 uppercase mb-2">Remediation Recommendations</h4>
                <div className="p-3 rounded bg-gray-900 border border-gray-800 text-xs text-gray-400 space-y-1">
                  <div>1. Block routing access to {selectedScan.domain} across internal perimeter firewalls and DNS sinkholes.</div>
                  <div>2. Revoke and rotate any session credentials inputted into this destination.</div>
                  <div>3. Submit domain indicator to upstream Threat Intelligence providers for telemetry verification.</div>
                </div>
              </div>
            </>
          ) : (
            <div className="py-16 text-center text-gray-500">No report selected</div>
          )}
        </div>
      </div>
    </div>
  );
};
