import React, { useState, useEffect } from 'react';
import { Cpu, CheckCircle, AlertTriangle, XCircle, RefreshCw } from 'lucide-react';
import { SystemServiceStatus } from '../types/threat';

export const SystemHealthPage: React.FC = () => {
  const [services, setServices] = useState<SystemServiceStatus[]>([]);
  const [loading, setLoading] = useState(false);
  const [mlMeta, setMlMeta] = useState<any>(null);

  const fetchHealth = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/system/health');
      if (res.ok) {
        const d = await res.json();
        setServices(d.services);
      }
      const sRes = await fetch('/api/settings');
      if (sRes.ok) {
        const sData = await sRes.json();
        setMlMeta(sData.mlModel);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
  }, []);

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6 font-mono">
      <div className="flex justify-between items-center">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-xl font-bold text-white tracking-wide">Platform Telemetry & System Diagnostics</h1>
            <span className="px-2 py-0.5 text-[10px] bg-emerald-950 text-emerald-400 border border-emerald-800 rounded">
              REAL SUBSYSTEMS
            </span>
          </div>
          <p className="text-xs text-gray-400 mt-1 font-sans">
            Live health verification of native Node.js network sockets, database persistence, and scikit-learn models.
          </p>
        </div>

        <button
          onClick={fetchHealth}
          disabled={loading}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-gray-900 border border-gray-800 text-xs text-gray-300 hover:text-white"
        >
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          <span>Inspect Now</span>
        </button>
      </div>

      {/* Services Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {services.map((svc, i) => (
          <div key={i} className="p-4 rounded-xl bg-[#0e1422] border border-gray-800 space-y-2">
            <div className="flex justify-between items-center">
              <span className="text-xs font-bold text-gray-200">{svc.name}</span>
              <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${
                svc.status === 'OPERATIONAL'
                  ? 'bg-emerald-950 text-emerald-400'
                  : svc.status === 'NOT_CONFIGURED'
                  ? 'bg-gray-800 text-gray-400'
                  : 'bg-red-950 text-red-400'
              }`}>
                {svc.status}
              </span>
            </div>
            <div className="text-[11px] text-gray-400">{svc.message}</div>
          </div>
        ))}
      </div>

      {/* Real ML Model Architecture */}
      {mlMeta && (
        <div className="p-6 rounded-xl bg-[#0e1422] border border-gray-800 space-y-4">
          <div className="flex items-center space-x-2">
            <Cpu size={18} className="text-red-400" />
            <h3 className="text-sm font-bold text-white uppercase">Active Neural / GBDT Inference Pipeline</h3>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
            <div className="p-3 rounded bg-gray-900 border border-gray-800">
              <div className="text-gray-500">MODEL VERSION</div>
              <div className="text-white font-bold mt-1">{mlMeta.version}</div>
            </div>
            <div className="p-3 rounded bg-gray-900 border border-gray-800">
              <div className="text-gray-500">BENCHMARK ACCURACY</div>
              <div className="text-emerald-400 font-bold mt-1">{(mlMeta.accuracy * 100).toFixed(1)}%</div>
            </div>
            <div className="p-3 rounded bg-gray-900 border border-gray-800">
              <div className="text-gray-500">PRECISION / RECALL</div>
              <div className="text-white font-bold mt-1">{(mlMeta.precision * 100).toFixed(1)}% / {(mlMeta.recall * 100).toFixed(1)}%</div>
            </div>
            <div className="p-3 rounded bg-gray-900 border border-gray-800">
              <div className="text-gray-500">CORPUS SIZE</div>
              <div className="text-white font-bold mt-1">{mlMeta.datasetSize.toLocaleString()} URLs</div>
            </div>
          </div>

          <div className="pt-2">
            <div className="text-xs text-gray-400 uppercase mb-2">Evaluated Lexical Features:</div>
            <div className="flex flex-wrap gap-2">
              {mlMeta.features?.map((f: string, i: number) => (
                <span key={i} className="px-2 py-1 rounded bg-gray-900 border border-gray-800 text-[11px] text-gray-300">
                  {f}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
