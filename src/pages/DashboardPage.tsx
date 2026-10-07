import React, { useEffect, useState } from 'react';
import { 
  ShieldAlert, ShieldCheck, AlertTriangle, Activity, 
  ExternalLink, Search, RefreshCw, ArrowUpRight, Clock, CheckCircle
} from 'lucide-react';
import { ScanResult } from '../types/threat';

interface DashboardProps {
  onSelectScan: (scanId: string) => void;
  onNavigateToAnalyzer: () => void;
}

export const DashboardPage: React.FC<DashboardProps> = ({ onSelectScan, onNavigateToAnalyzer }) => {
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState<boolean>(true);

  const fetchStats = async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/dashboard/stats');
      if (res.ok) {
        const data = await res.json();
        setStats(data);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Title & Refresh */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-gray-800">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-xl font-bold text-white tracking-wide">SOC Command Center</h1>
            <span className="px-2 py-0.5 text-[10px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-800 rounded">
              LIVE TELEMETRY
            </span>
          </div>
          <p className="text-xs text-gray-400 mt-1">Real-time database aggregated threat activity & active network telemetry</p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={fetchStats}
            disabled={loading}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-gray-900 border border-gray-800 text-xs text-gray-300 hover:text-white hover:border-gray-700 transition-all"
          >
            <RefreshCw size={14} className={loading ? 'animate-spin text-red-400' : ''} />
            <span>Refresh Telemetry</span>
          </button>
          <button
            onClick={onNavigateToAnalyzer}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-xs font-semibold text-white shadow-sm shadow-red-950 transition-all"
          >
            <ShieldAlert size={14} />
            <span>New Deep Scan</span>
          </button>
        </div>
      </div>

      {/* Metrics Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-[#0e1422] border border-gray-800">
          <div className="text-[11px] font-mono uppercase tracking-wider text-gray-400">Total Scans Performed</div>
          <div className="text-2xl font-bold font-mono text-white mt-2">
            {stats ? stats.totalScans : '...'}
          </div>
          <div className="text-[10px] text-gray-500 mt-1">Directly recorded in database</div>
        </div>

        <div className="p-4 rounded-xl bg-[#0e1422] border border-red-900/30">
          <div className="text-[11px] font-mono uppercase tracking-wider text-red-400">Malicious Detections</div>
          <div className="text-2xl font-bold font-mono text-red-500 mt-2">
            {stats ? stats.maliciousCount : '...'}
          </div>
          <div className="text-[10px] text-red-400/70 mt-1">High-confidence confirmed IOCs</div>
        </div>

        <div className="p-4 rounded-xl bg-[#0e1422] border border-amber-900/30">
          <div className="text-[11px] font-mono uppercase tracking-wider text-amber-400">Suspicious Indicators</div>
          <div className="text-2xl font-bold font-mono text-amber-500 mt-2">
            {stats ? stats.suspiciousCount : '...'}
          </div>
          <div className="text-[10px] text-amber-400/70 mt-1">Anomalies requiring inspection</div>
        </div>

        <div className="p-4 rounded-xl bg-[#0e1422] border border-emerald-900/30">
          <div className="text-[11px] font-mono uppercase tracking-wider text-emerald-400">Clean Targets</div>
          <div className="text-2xl font-bold font-mono text-emerald-500 mt-2">
            {stats ? stats.safeCount : '...'}
          </div>
          <div className="text-[10px] text-emerald-400/70 mt-1">Verified legitimate entities</div>
        </div>
      </div>

      {/* Live Activity & Alerts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Scans Table */}
        <div className="lg:col-span-2 rounded-xl bg-[#0e1422] border border-gray-800 p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-bold text-gray-200 uppercase tracking-wide font-mono flex items-center space-x-2">
              <Activity size={16} className="text-red-400" />
              <span>Recent Investigated Indicators</span>
            </h2>
            <button onClick={onNavigateToAnalyzer} className="text-xs text-red-400 hover:underline">
              Analyze New Target
            </button>
          </div>

          {stats && stats.recentScans.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-gray-800 text-gray-400 font-mono">
                    <th className="pb-2">TARGET</th>
                    <th className="pb-2">TYPE</th>
                    <th className="pb-2">RISK</th>
                    <th className="pb-2">SCORE</th>
                    <th className="pb-2">TIME</th>
                    <th className="pb-2 text-right">ACTION</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/60 font-mono">
                  {stats.recentScans.map((s: ScanResult) => (
                    <tr key={s.id} className="hover:bg-gray-900/40 transition-colors">
                      <td className="py-2.5 max-w-[200px] truncate text-gray-200">
                        {s.target}
                      </td>
                      <td className="py-2.5 text-gray-400">{s.type}</td>
                      <td className="py-2.5">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          s.overallRisk === 'MALICIOUS'
                            ? 'bg-red-950 text-red-400 border border-red-800'
                            : s.overallRisk === 'SUSPICIOUS'
                            ? 'bg-amber-950 text-amber-400 border border-amber-800'
                            : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                        }`}>
                          {s.overallRisk}
                        </span>
                      </td>
                      <td className="py-2.5 font-bold text-gray-300">{s.riskScore}/100</td>
                      <td className="py-2.5 text-gray-500 text-[10px]">
                        {new Date(s.createdAt).toLocaleTimeString()}
                      </td>
                      <td className="py-2.5 text-right">
                        <button
                          onClick={() => onSelectScan(s.id)}
                          className="px-2 py-1 rounded bg-gray-800 hover:bg-red-950 hover:text-red-400 text-gray-300 text-[11px] transition-colors"
                        >
                          Details
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="py-12 text-center text-gray-500">
              <Activity size={32} className="mx-auto mb-2 opacity-30" />
              <div className="text-sm font-medium text-gray-400">No security activity yet</div>
              <p className="text-xs text-gray-500 mt-1 max-w-sm mx-auto">
                No URLs, domains, or IPs have been investigated yet. Submit your first indicator for live multi-engine inspection.
              </p>
              <button
                onClick={onNavigateToAnalyzer}
                className="mt-4 px-4 py-2 bg-red-600 hover:bg-red-500 text-white text-xs font-semibold rounded-lg transition-colors"
              >
                Launch First Deep Scan
              </button>
            </div>
          )}
        </div>

        {/* Live Security Alerts */}
        <div className="rounded-xl bg-[#0e1422] border border-gray-800 p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-bold text-gray-200 uppercase tracking-wide font-mono flex items-center space-x-2">
              <AlertTriangle size={16} className="text-amber-400" />
              <span>Active SOC Alerts</span>
            </h2>
            <span className="text-[10px] font-mono text-gray-500">
              {stats ? stats.openAlerts : 0} OPEN
            </span>
          </div>

          {stats && stats.recentAlerts.length > 0 ? (
            <div className="space-y-3">
              {stats.recentAlerts.map((alt: any) => (
                <div key={alt.id} className="p-3 rounded-lg bg-gray-900/60 border border-gray-800/80">
                  <div className="flex items-center justify-between">
                    <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold ${
                      alt.severity === 'CRITICAL' ? 'bg-red-950 text-red-400 border border-red-800' : 'bg-amber-950 text-amber-400 border border-amber-800'
                    }`}>
                      {alt.severity}
                    </span>
                    <span className="text-[10px] text-gray-500 font-mono">
                      {new Date(alt.createdAt).toLocaleTimeString()}
                    </span>
                  </div>
                  <div className="text-xs font-semibold text-gray-200 mt-1.5 truncate">{alt.title}</div>
                  <div className="text-[11px] text-gray-400 mt-0.5 line-clamp-2">{alt.description}</div>
                </div>
              ))}
            </div>
          ) : (
            <div className="py-12 text-center text-gray-500">
              <CheckCircle size={32} className="mx-auto mb-2 opacity-30 text-emerald-500" />
              <div className="text-sm font-medium text-gray-400">Zero Pending Alerts</div>
              <p className="text-xs text-gray-500 mt-1">
                Your monitored indicators and network perimeter currently have no unresolved triggers.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
